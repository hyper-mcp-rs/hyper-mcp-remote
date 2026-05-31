//! Bidirectional MCP proxy between a local stdio server (this process's
//! stdin/stdout) and a remote Streamable-HTTP MCP server.
//!
//! The implementation closely mirrors `hyper-mcp-proxy`, but with the roles
//! inverted:
//!
//! ```text
//! stdio MCP client  ──stdin/stdout──▶  ProxyHandler (ServerHandler)
//!                                              │
//!                                              ▼
//!                                  Peer<RoleClient> ──HTTP──▶  Remote MCP server
//!                                              │
//!                                              ▲
//!                                  RemoteClientHandler (ClientHandler)
//! ```
//!
//! `ProxyHandler` implements [`rmcp::ServerHandler`] for the local stdio
//! connection and forwards every typed MCP call to the remote via a
//! [`Peer<RoleClient>`]. `RemoteClientHandler` implements
//! [`rmcp::ClientHandler`] for the remote connection and forwards reverse
//! traffic (sampling, elicitation, list_roots, log notifications, …) back to
//! the stdio client.
//!
//! Capability reflection: the result of [`ProxyHandler::initialize`] is the
//! upstream remote's own [`InitializeResult`] (with only `server_info`
//! patched to identify the proxy), so the local client sees exactly the
//! capabilities the remote advertises.

use std::sync::Mutex;

use anyhow::Result;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, CancelledNotificationParam, ClientInfo,
    CompleteRequestParams, CompleteResult, CreateElicitationRequestParams, CreateElicitationResult,
    CreateMessageRequestParams, CreateMessageResult, ElicitationResponseNotificationParam,
    ErrorCode, ErrorData, GetPromptRequestParams, GetPromptResult, Implementation,
    InitializeRequestParams, InitializeResult, ListPromptsResult, ListResourceTemplatesResult,
    ListResourcesResult, ListRootsResult, ListToolsResult, LoggingMessageNotificationParam,
    PaginatedRequestParams, ProgressNotificationParam, ReadResourceRequestParams,
    ReadResourceResult, ResourceUpdatedNotificationParam, ServerCapabilities,
    SetLevelRequestParams, SubscribeRequestParams, UnsubscribeRequestParams,
};
use rmcp::service::{
    NotificationContext, Peer, RequestContext, RoleClient, RoleServer, RunningService, ServiceExt,
};
use rmcp::{ClientHandler, ServerHandler};
use tokio::sync::OnceCell;

use crate::transport::RemoteTransport;

// ---------------------------------------------------------------------------
// RemoteClientHandler — relays remote→client traffic back to the stdio client
// ---------------------------------------------------------------------------

/// A [`ClientHandler`] that runs against the remote MCP server connection
/// and forwards every server→client request and notification back to the
/// local stdio client via `upstream`.
pub struct RemoteClientHandler {
    upstream: Peer<RoleServer>,
    /// `ClientInfo` advertised to the remote during the outbound handshake.
    ///
    /// Built from the local stdio client's own `initialize` request so that
    /// the remote sees the *actual* client's protocol version and
    /// capabilities (sampling / elicitation / roots), not the rmcp default.
    /// `client_info.name` is suffixed with `(via hyper-mcp-remote)` so the
    /// remote can still tell traffic is being proxied.
    proxied_info: ClientInfo,
}

impl ClientHandler for RemoteClientHandler {
    fn get_info(&self) -> ClientInfo {
        self.proxied_info.clone()
    }
    // -- Requests originated by the remote server -------------------------

    #[tracing::instrument(skip_all, fields(dir = "remote←local"))]
    async fn create_message(
        &self,
        params: CreateMessageRequestParams,
        _ctx: RequestContext<RoleClient>,
    ) -> Result<CreateMessageResult, ErrorData> {
        self.upstream
            .create_message(params)
            .await
            .map_err(upstream_error)
    }

    #[tracing::instrument(skip_all, fields(dir = "remote←local"))]
    async fn list_roots(
        &self,
        _ctx: RequestContext<RoleClient>,
    ) -> Result<ListRootsResult, ErrorData> {
        self.upstream.list_roots().await.map_err(upstream_error)
    }

    #[tracing::instrument(skip_all, fields(dir = "remote←local"))]
    async fn create_elicitation(
        &self,
        request: CreateElicitationRequestParams,
        _ctx: RequestContext<RoleClient>,
    ) -> Result<CreateElicitationResult, ErrorData> {
        self.upstream
            .create_elicitation(request)
            .await
            .map_err(upstream_error)
    }

    // -- Notifications originated by the remote server --------------------

    #[tracing::instrument(skip_all, fields(dir = "remote→local"))]
    async fn on_cancelled(
        &self,
        params: CancelledNotificationParam,
        _ctx: NotificationContext<RoleClient>,
    ) {
        if let Err(e) = self.upstream.notify_cancelled(params).await {
            tracing::warn!(error = %e, "failed to forward cancelled to stdio client");
        }
    }

    /// Demoted to `debug` because progress notifications can fire many
    /// times per second during long-running tool calls.
    #[tracing::instrument(level = "debug", skip_all, fields(dir = "remote→local"))]
    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _ctx: NotificationContext<RoleClient>,
    ) {
        if let Err(e) = self.upstream.notify_progress(params).await {
            tracing::warn!(error = %e, "failed to forward progress to stdio client");
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(dir = "remote→local"))]
    async fn on_logging_message(
        &self,
        params: LoggingMessageNotificationParam,
        _ctx: NotificationContext<RoleClient>,
    ) {
        if let Err(e) = self.upstream.notify_logging_message(params).await {
            tracing::warn!(error = %e, "failed to forward logging message to stdio client");
        }
    }

    #[tracing::instrument(skip_all, fields(dir = "remote→local", uri = %params.uri))]
    async fn on_resource_updated(
        &self,
        params: ResourceUpdatedNotificationParam,
        _ctx: NotificationContext<RoleClient>,
    ) {
        if let Err(e) = self.upstream.notify_resource_updated(params).await {
            tracing::warn!(error = %e, "failed to forward resource_updated to stdio client");
        }
    }

    #[tracing::instrument(skip_all, fields(dir = "remote→local"))]
    async fn on_resource_list_changed(&self, _ctx: NotificationContext<RoleClient>) {
        if let Err(e) = self.upstream.notify_resource_list_changed().await {
            tracing::warn!(error = %e, "failed to forward resource_list_changed to stdio client");
        }
    }

    #[tracing::instrument(skip_all, fields(dir = "remote→local"))]
    async fn on_tool_list_changed(&self, _ctx: NotificationContext<RoleClient>) {
        if let Err(e) = self.upstream.notify_tool_list_changed().await {
            tracing::warn!(error = %e, "failed to forward tool_list_changed to stdio client");
        }
    }

    #[tracing::instrument(skip_all, fields(dir = "remote→local"))]
    async fn on_prompt_list_changed(&self, _ctx: NotificationContext<RoleClient>) {
        if let Err(e) = self.upstream.notify_prompt_list_changed().await {
            tracing::warn!(error = %e, "failed to forward prompt_list_changed to stdio client");
        }
    }

    #[tracing::instrument(skip_all, fields(dir = "remote→local"))]
    async fn on_url_elicitation_notification_complete(
        &self,
        params: ElicitationResponseNotificationParam,
        _ctx: NotificationContext<RoleClient>,
    ) {
        if let Err(e) = self.upstream.notify_url_elicitation_completed(params).await {
            tracing::warn!(error = %e, "failed to forward elicitation completion to stdio client");
        }
    }
}

// ---------------------------------------------------------------------------
// ProxyHandler — implements ServerHandler for the local stdio connection
// ---------------------------------------------------------------------------

/// State established once the remote connection is up.
struct Remote {
    /// Peer used to call methods on the remote MCP server.
    peer: Peer<RoleClient>,
    /// Initialization result advertised by the remote server.
    init_result: InitializeResult,
    /// Background task keeping the remote client service alive.
    _service_handle: tokio::task::JoinHandle<()>,
}

/// `ServerHandler` for the local stdio connection. Lazily connects to the
/// remote MCP server on the first `initialize` request and forwards every
/// subsequent message through.
pub struct ProxyHandler {
    /// `std::sync::Mutex` (not `tokio::sync::Mutex`) so that locking does not
    /// produce a non-`Send` guard across an `await` point: we only ever do a
    /// brief, synchronous `take()` while the connection is being established.
    transport: Mutex<Option<RemoteTransport>>,
    remote: OnceCell<Remote>,
}

impl ProxyHandler {
    /// Wrap a freshly built [`RemoteTransport`]. The remote connection is
    /// not opened until the local client sends `initialize`.
    pub fn new(transport: RemoteTransport) -> Self {
        Self {
            transport: Mutex::new(Some(transport)),
            remote: OnceCell::new(),
        }
    }

    /// Borrow the remote peer, returning a clear error if `initialize`
    /// hasn't completed yet.
    fn peer(&self) -> Result<&Peer<RoleClient>, ErrorData> {
        self.remote
            .get()
            .map(|r| &r.peer)
            .ok_or_else(|| internal_error("proxy session not yet initialized"))
    }

    /// Connect to the remote MCP server, performing the MCP handshake on
    /// behalf of the local stdio client. `local_init` is the parameters of
    /// the local client's own `initialize` request so the proxy can forward
    /// the client's true capability set to the remote.
    #[tracing::instrument(skip_all)]
    async fn connect(
        &self,
        upstream: Peer<RoleServer>,
        local_init: InitializeRequestParams,
    ) -> Result<&Remote, ErrorData> {
        self.remote
            .get_or_try_init(|| async {
                let transport = {
                    let mut guard = self
                        .transport
                        .lock()
                        .map_err(|_| internal_error("transport mutex poisoned"))?;
                    guard
                        .take()
                        .ok_or_else(|| internal_error("remote transport already consumed"))?
                };

                let handler = RemoteClientHandler {
                    upstream,
                    proxied_info: build_proxied_client_info(local_init),
                };

                let running: RunningService<RoleClient, RemoteClientHandler> = match transport {
                    RemoteTransport::Anonymous(t) => {
                        handler.serve(t).await.map_err(remote_error)?
                    }
                    RemoteTransport::Authorized(t) => {
                        handler.serve(t).await.map_err(remote_error)?
                    }
                };

                let peer = running.peer().clone();

                // Capability reflection: present whatever the remote sent us
                // on `initialize`, but identify the proxy as the server
                // implementation so a curious client can tell the difference.
                let mut init_result = running
                    .peer_info()
                    .cloned()
                    .unwrap_or_else(|| InitializeResult::new(ServerCapabilities::default()));
                init_result.server_info =
                    Implementation::new("hyper-mcp-remote", env!("CARGO_PKG_VERSION"));

                let handle = tokio::spawn(async move {
                    if let Err(e) = running.waiting().await {
                        tracing::warn!(error = %e, "remote MCP service ended with error");
                    } else {
                        tracing::info!("remote MCP service ended");
                    }
                });

                Ok::<_, ErrorData>(Remote {
                    peer,
                    init_result,
                    _service_handle: handle,
                })
            })
            .await
    }
}

// ---------------------------------------------------------------------------
// ServerHandler implementation — forward every typed call to the remote
// ---------------------------------------------------------------------------

impl ServerHandler for ProxyHandler {
    #[tracing::instrument(
        skip_all,
        fields(
            dir = "local→remote",
            client = %request.client_info.name,
            client_version = %request.client_info.version,
            protocol = ?request.protocol_version,
        )
    )]
    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        let remote = self.connect(context.peer.clone(), request).await?;
        Ok(remote.init_result.clone())
    }

    // -- Tools -----------------------------------------------------------

    #[tracing::instrument(skip_all, fields(dir = "local→remote"))]
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.peer()?.list_tools(request).await.map_err(remote_error)
    }

    #[tracing::instrument(skip_all, fields(dir = "local→remote", tool = %request.name))]
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.peer()?.call_tool(request).await.map_err(remote_error)
    }

    // -- Resources -------------------------------------------------------

    #[tracing::instrument(skip_all, fields(dir = "local→remote"))]
    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        self.peer()?
            .list_resources(request)
            .await
            .map_err(remote_error)
    }

    #[tracing::instrument(skip_all, fields(dir = "local→remote"))]
    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        self.peer()?
            .list_resource_templates(request)
            .await
            .map_err(remote_error)
    }

    #[tracing::instrument(skip_all, fields(dir = "local→remote", uri = %request.uri))]
    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        self.peer()?
            .read_resource(request)
            .await
            .map_err(remote_error)
    }

    #[tracing::instrument(skip_all, fields(dir = "local→remote", uri = %request.uri))]
    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.peer()?.subscribe(request).await.map_err(remote_error)
    }

    #[tracing::instrument(skip_all, fields(dir = "local→remote", uri = %request.uri))]
    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.peer()?
            .unsubscribe(request)
            .await
            .map_err(remote_error)
    }

    // -- Prompts ---------------------------------------------------------

    #[tracing::instrument(skip_all, fields(dir = "local→remote"))]
    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        self.peer()?
            .list_prompts(request)
            .await
            .map_err(remote_error)
    }

    #[tracing::instrument(skip_all, fields(dir = "local→remote", prompt = %request.name))]
    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, ErrorData> {
        self.peer()?.get_prompt(request).await.map_err(remote_error)
    }

    // -- Completions -----------------------------------------------------

    #[tracing::instrument(skip_all, fields(dir = "local→remote"))]
    async fn complete(
        &self,
        request: CompleteRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, ErrorData> {
        self.peer()?.complete(request).await.map_err(remote_error)
    }

    // -- Logging ---------------------------------------------------------

    #[tracing::instrument(skip_all, fields(dir = "local→remote", level = ?request.level))]
    async fn set_level(
        &self,
        request: SetLevelRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.peer()?.set_level(request).await.map_err(remote_error)
    }

    // -- Notifications (local stdio client → remote) ----------------------

    #[tracing::instrument(skip_all, fields(dir = "local→remote"))]
    async fn on_cancelled(
        &self,
        notification: CancelledNotificationParam,
        _ctx: NotificationContext<RoleServer>,
    ) {
        if let Ok(peer) = self.peer()
            && let Err(e) = peer.notify_cancelled(notification).await
        {
            tracing::warn!(error = %e, "failed to forward cancellation to remote");
        }
    }

    /// Demoted to `debug` because progress notifications can fire many
    /// times per second during long-running tool calls.
    #[tracing::instrument(level = "debug", skip_all, fields(dir = "local→remote"))]
    async fn on_progress(
        &self,
        notification: ProgressNotificationParam,
        _ctx: NotificationContext<RoleServer>,
    ) {
        if let Ok(peer) = self.peer()
            && let Err(e) = peer.notify_progress(notification).await
        {
            tracing::warn!(error = %e, "failed to forward progress to remote");
        }
    }

    #[tracing::instrument(skip_all, fields(dir = "local→remote"))]
    async fn on_initialized(&self, _ctx: NotificationContext<RoleServer>) {
        // The rmcp client we manage internally sends its own `initialized`
        // notification to the remote during `serve(...)`. We deliberately do
        // not forward the local client's `initialized` again.
        tracing::debug!("local client sent initialized");
    }

    #[tracing::instrument(skip_all, fields(dir = "local→remote"))]
    async fn on_roots_list_changed(&self, _ctx: NotificationContext<RoleServer>) {
        if let Ok(peer) = self.peer()
            && let Err(e) = peer.notify_roots_list_changed().await
        {
            tracing::warn!(error = %e, "failed to forward roots_list_changed to remote");
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the [`ClientInfo`] the proxy will use when initializing the remote
/// MCP server connection.
///
/// We propagate the **local client's** capabilities and protocol version
/// verbatim, only rewriting `client_info.name` so the remote can see traffic
/// is being proxied (e.g. `"Claude Desktop (via hyper-mcp-remote 0.1.0)"`).
/// This mirrors `mcp-remote`'s name-suffixing behavior and ensures the
/// remote will continue to send sampling / elicitation / roots requests if
/// (and only if) the local client actually supports them.
fn build_proxied_client_info(mut local: InitializeRequestParams) -> ClientInfo {
    const PROXY_TAG: &str = concat!(" (via hyper-mcp-remote ", env!("CARGO_PKG_VERSION"), ")");
    local.client_info.name.push_str(PROXY_TAG);
    // `InitializeRequestParams` and `ClientInfo` are the same struct under
    // a different alias in rmcp 1.7.
    local
}

fn internal_error(msg: impl Into<String>) -> ErrorData {
    ErrorData::new(ErrorCode::INTERNAL_ERROR, msg.into(), None)
}

fn remote_error(e: impl std::fmt::Display) -> ErrorData {
    ErrorData::new(
        ErrorCode::INTERNAL_ERROR,
        format!("remote MCP server error: {e}"),
        None,
    )
}

fn upstream_error(e: impl std::fmt::Display) -> ErrorData {
    ErrorData::new(
        ErrorCode::INTERNAL_ERROR,
        format!("local stdio client error: {e}"),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ProtocolVersion;

    #[test]
    fn proxied_client_info_preserves_capabilities_and_tags_name() {
        let mut input = InitializeRequestParams::default();
        input.client_info.name = "Test Client".to_string();
        input.client_info.version = "9.9.9".to_string();
        input.protocol_version = ProtocolVersion::default();

        let out = build_proxied_client_info(input.clone());

        assert_eq!(out.client_info.version, "9.9.9");
        assert!(
            out.client_info.name.starts_with("Test Client"),
            "name should keep the original prefix; got {:?}",
            out.client_info.name
        );
        assert!(
            out.client_info.name.contains("hyper-mcp-remote"),
            "name should be suffixed with proxy identity; got {:?}",
            out.client_info.name
        );
        assert_eq!(
            out.capabilities, input.capabilities,
            "client capabilities must be forwarded verbatim"
        );
        assert_eq!(out.protocol_version, input.protocol_version);
    }

    #[test]
    fn helper_error_codes_are_internal_error() {
        let e1 = internal_error("x");
        let e2 = remote_error("y");
        let e3 = upstream_error("z");
        assert_eq!(e1.code, ErrorCode::INTERNAL_ERROR);
        assert_eq!(e2.code, ErrorCode::INTERNAL_ERROR);
        assert_eq!(e3.code, ErrorCode::INTERNAL_ERROR);
    }

    #[test]
    fn remote_and_upstream_have_distinct_prefixes() {
        assert!(remote_error("boom").message.contains("remote MCP server"));
        assert!(
            upstream_error("boom")
                .message
                .contains("local stdio client")
        );
    }

    // Silence "unused" warning if the type is only used through trait objects.
}
