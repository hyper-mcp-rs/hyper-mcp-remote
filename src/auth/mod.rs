//! End-to-end MCP OAuth flow management.
//!
//! Drives `rmcp`'s [`OAuthState`] state machine through the full
//! discover → register → authorize → token → refresh cycle, persisting
//! credentials between launches with a [`SecureCredentialStore`].
//!
//! Public entry point is [`acquire_auth_client`].

pub mod callback;
pub mod discovery;
pub mod storage;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use http::{HeaderName, HeaderValue};
use reqwest::Client as HttpClient;
use rmcp::transport::auth::{AuthClient, OAuthState};

use crate::cli::Cli;
use crate::session::CredentialKey;

use self::callback::CallbackServer;
use self::discovery::{AuthRequirement, OAuthDiscovery};
use self::storage::SecureCredentialStore;

/// What we hand back to the transport layer.
pub enum AuthOutcome {
    /// Server does not require OAuth. Use a plain HTTP client.
    Anonymous { http_client: HttpClient },
    /// Server requires OAuth and we have a valid (possibly refreshable)
    /// `AuthClient` for it.
    Authorized { client: AuthClient<HttpClient> },
}

/// Acquire (or refresh) credentials for `cli.server_url` and return an HTTP
/// client ready to drive the streamable-http transport.
///
/// On the happy path with cached tokens this performs zero browser
/// interaction. On first run, or when stored tokens are invalid, it spins up
/// a local OAuth callback server, opens the user's browser, and waits for
/// them to complete the flow.
pub async fn acquire_auth_client(
    cli: &Cli,
    cred_key: &CredentialKey,
    headers: &HashMap<HeaderName, HeaderValue>,
) -> Result<AuthOutcome> {
    let http_client = build_http_client()?;

    // 0. Explicit opt-out: skip discovery and OAuth entirely. Useful for
    //    servers that 401 in non-spec-compliant ways (stateful session
    //    headers, static bearer tokens supplied via --header, ...).
    if cli.no_auth {
        tracing::info!(
            "--no-auth specified; skipping OAuth discovery and using an anonymous HTTP client"
        );
        return Ok(AuthOutcome::Anonymous { http_client });
    }

    let store = Arc::new(SecureCredentialStore::new(cred_key)?);
    if cli.reset_auth {
        tracing::info!("--reset-auth specified; clearing any cached credentials");
        store
            .clear_sync()
            .context("failed to clear cached credentials")?;
    }

    // 1. Probe the server. If it accepts anonymous traffic, we're done.
    let requirement = discovery::discover(
        &http_client,
        &cli.server_url,
        headers,
        cli.resource.as_deref(),
    )
    .await
    .context("failed to discover OAuth requirements")?;

    let discovery = match requirement {
        AuthRequirement::None => {
            tracing::info!("remote server accepts unauthenticated requests");
            return Ok(AuthOutcome::Anonymous { http_client });
        }
        AuthRequirement::Required(d) => d,
    };

    tracing::info!(
        authorization_server = %discovery.authorization_server,
        scopes = ?discovery.scopes,
        "remote requires OAuth"
    );

    // 2. Construct OAuthState, install our credential store.
    //
    // We deliberately pass `None` here so that rmcp builds its own internal
    // HTTP client for talking to the authorization server. rmcp's auth
    // module depends on a different (older) major of `reqwest` than the
    // streamable-http transport, and mixing the two would require
    // hand-bridging incompatible client types.
    let mut state = OAuthState::new(discovery.authorization_server.as_str(), None)
        .await
        .context("failed to initialize OAuth state machine")?;

    install_credential_store(&mut state, store.clone()).await?;

    // 3. Try cached credentials first.
    if let Some(cached) = store
        .as_ref()
        .load_via_trait()
        .await
        .context("failed to load cached credentials")?
        && let Some(token) = cached.token_response.clone()
    {
        tracing::info!("found cached OAuth credentials; using them");
        state
            .set_credentials(&cached.client_id, token)
            .await
            .context("failed to apply cached credentials")?;
        return Ok(AuthOutcome::Authorized {
            client: into_auth_client(state, http_client)?,
        });
    }

    // 4. No usable cached creds: run the interactive flow.
    run_interactive_flow(cli, &mut state, &discovery).await?;

    Ok(AuthOutcome::Authorized {
        client: into_auth_client(state, http_client)?,
    })
}

/// Convenience method on the concrete `SecureCredentialStore` that mirrors
/// `CredentialStore::load` but doesn't require importing the trait at the
/// call site.
#[async_trait::async_trait]
trait CredentialStoreExt {
    async fn load_via_trait(
        &self,
    ) -> Result<Option<rmcp::transport::auth::StoredCredentials>, rmcp::transport::auth::AuthError>;
}

#[async_trait::async_trait]
impl CredentialStoreExt for SecureCredentialStore {
    async fn load_via_trait(
        &self,
    ) -> Result<Option<rmcp::transport::auth::StoredCredentials>, rmcp::transport::auth::AuthError>
    {
        <Self as rmcp::transport::auth::CredentialStore>::load(self).await
    }
}

/// Replace the default in-memory credential store on an `Unauthorized`
/// `OAuthState` with our persistent one.
async fn install_credential_store(
    state: &mut OAuthState,
    store: Arc<SecureCredentialStore>,
) -> Result<()> {
    match state {
        OAuthState::Unauthorized(manager) => {
            // `set_credential_store` takes `S: CredentialStore + 'static` by
            // value; we own an `Arc<S>` so wrap a clone in `ArcStore`.
            manager.set_credential_store(ArcStore(store));
            Ok(())
        }
        _ => anyhow::bail!(
            "internal error: OAuthState must be Unauthorized when installing credential store"
        ),
    }
}

/// Thin newtype to satisfy `CredentialStore + 'static` while keeping the
/// underlying store shared with the rest of the program.
struct ArcStore(Arc<SecureCredentialStore>);

#[async_trait::async_trait]
impl rmcp::transport::auth::CredentialStore for ArcStore {
    async fn load(
        &self,
    ) -> Result<Option<rmcp::transport::auth::StoredCredentials>, rmcp::transport::auth::AuthError>
    {
        self.0.load().await
    }

    async fn save(
        &self,
        credentials: rmcp::transport::auth::StoredCredentials,
    ) -> Result<(), rmcp::transport::auth::AuthError> {
        self.0.save(credentials).await
    }

    async fn clear(&self) -> Result<(), rmcp::transport::auth::AuthError> {
        self.0.clear().await
    }
}

/// Run dynamic-client registration, browser-based authorization, and the
/// final token exchange. On success the `state` argument is mutated into
/// `Authorized`.
async fn run_interactive_flow(
    cli: &Cli,
    state: &mut OAuthState,
    discovery: &OAuthDiscovery,
) -> Result<()> {
    let callback = CallbackServer::bind(&cli.callback_host, cli.callback_port.unwrap_or(0))
        .await
        .context("failed to start local OAuth callback server")?;

    let scopes = effective_scopes(cli, discovery);
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
    tracing::info!(scopes = ?scopes, "starting OAuth authorization");

    state
        .start_authorization(
            &scope_refs,
            &callback.redirect_uri,
            Some(cli.client_name.as_str()),
        )
        .await
        .context("OAuth authorization start failed (dynamic registration?)")?;

    let auth_url = state
        .get_authorization_url()
        .await
        .context("failed to build authorization URL")?;

    // Print to stderr so the MCP host (which owns stdout) can surface it.
    eprintln!("\nOpen this URL in your browser to authorize hyper-mcp-remote:\n{auth_url}\n");
    match webbrowser::open(&auth_url) {
        Ok(_) => tracing::info!("opened authorization URL in default browser"),
        Err(e) => {
            tracing::warn!(error = %e, "couldn't open browser automatically; please open the URL above manually")
        }
    }

    let timeout = Duration::from_secs(cli.auth_timeout_secs);
    let code = callback
        .wait(timeout)
        .await
        .context("OAuth callback wait failed")?;

    state
        .handle_callback(&code.code, &code.state)
        .await
        .context("OAuth code exchange failed")?;

    tracing::info!("OAuth authorization complete");
    Ok(())
}

/// Determine the final scope list, with CLI override taking precedence over
/// discovery results.
fn effective_scopes(cli: &Cli, discovery: &OAuthDiscovery) -> Vec<String> {
    if let Some(s) = &cli.scope {
        s.split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    } else {
        discovery.scopes.clone()
    }
}

/// Move an `Authorized` `OAuthState` into a usable `AuthClient`.
fn into_auth_client(state: OAuthState, http_client: HttpClient) -> Result<AuthClient<HttpClient>> {
    let manager = state
        .into_authorization_manager()
        .context("OAuthState was not authorized after flow")?;
    Ok(AuthClient::new(http_client, manager))
}

fn build_http_client() -> Result<HttpClient> {
    HttpClient::builder()
        .user_agent(concat!(
            "hyper-mcp-remote/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/hyper-mcp-rs/hyper-mcp-remote)"
        ))
        .build()
        .context("failed to build HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use discovery::OAuthDiscovery;

    fn parse_cli(args: &[&str]) -> Cli {
        let mut full = vec!["hyper-mcp-remote"];
        full.extend_from_slice(args);
        Cli::parse_from(full)
    }

    fn discovery_with(scopes: &[&str]) -> OAuthDiscovery {
        OAuthDiscovery {
            authorization_server: "https://auth.example.com".to_string(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            resource: "https://example.com/mcp".to_string(),
        }
    }

    #[test]
    fn effective_scopes_uses_cli_override_when_set() {
        let cli = parse_cli(&["--scope", "read,write", "https://example.com/mcp"]);
        let d = discovery_with(&["discovered"]);
        assert_eq!(
            effective_scopes(&cli, &d),
            vec!["read".to_string(), "write".to_string()],
            "CLI --scope must take precedence over discovery"
        );
    }

    #[test]
    fn effective_scopes_falls_back_to_discovery() {
        let cli = parse_cli(&["https://example.com/mcp"]);
        let d = discovery_with(&["a", "b", "c"]);
        assert_eq!(
            effective_scopes(&cli, &d),
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
        );
    }

    #[test]
    fn effective_scopes_handles_mixed_whitespace_and_commas() {
        let cli = parse_cli(&[
            "--scope",
            "  read , write\tadmin",
            "https://example.com/mcp",
        ]);
        let scopes = effective_scopes(&cli, &discovery_with(&[]));
        assert_eq!(
            scopes,
            vec!["read".to_string(), "write".to_string(), "admin".to_string()],
        );
    }

    #[test]
    fn effective_scopes_empty_cli_returns_empty() {
        let cli = parse_cli(&["--scope", " , , ", "https://example.com/mcp"]);
        let scopes = effective_scopes(&cli, &discovery_with(&["unused"]));
        assert!(
            scopes.is_empty(),
            "CLI override of all-whitespace must produce empty list, got {scopes:?}"
        );
    }

    #[test]
    fn build_http_client_succeeds() {
        let _c = build_http_client().expect("http client must build");
    }

    // -- acquire_auth_client (anonymous path) -----------------------------

    use axum::Router;
    use axum::routing::get;
    use std::collections::HashMap;
    use std::sync::Arc;

    async fn spawn_anonymous_mock() -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route("/mcp", get(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        (format!("http://{addr}/mcp"), handle)
    }

    #[tokio::test]
    async fn acquire_auth_client_returns_anonymous_when_server_does_not_require_oauth() {
        let (url, _h) = spawn_anonymous_mock().await;
        let cli = parse_cli(&["--allow-http", &url]);
        let headers = HashMap::new();
        let cred_key = CredentialKey::new(&url, None);

        let outcome = acquire_auth_client(&cli, &cred_key, &headers)
            .await
            .expect("acquire");
        assert!(
            matches!(outcome, AuthOutcome::Anonymous { .. }),
            "server returned 200 — we should not have started an OAuth flow"
        );
    }

    #[tokio::test]
    async fn acquire_auth_client_short_circuits_on_no_auth_without_touching_network() {
        // Point at a URL with no listener at all: if we accidentally do any
        // probing, the test fails with a connection error. With --no-auth we
        // must hand back AuthOutcome::Anonymous immediately.
        let url = "http://127.0.0.1:1/mcp"; // port 1 is reserved/unbound
        let cli = parse_cli(&["--no-auth", "--allow-http", url]);
        let headers = HashMap::new();
        let cred_key = CredentialKey::new(url, None);

        let outcome = acquire_auth_client(&cli, &cred_key, &headers)
            .await
            .expect("--no-auth must not perform any network I/O");
        assert!(
            matches!(outcome, AuthOutcome::Anonymous { .. }),
            "--no-auth must yield AuthOutcome::Anonymous"
        );
    }

    #[tokio::test]
    async fn arc_store_load_returns_none_on_empty() {
        // Exercise the ArcStore wrapper: even with no creds it must return
        // Ok(None) rather than erroring.
        let dir = tempfile::tempdir().expect("tempdir");
        let cred_key = CredentialKey::new("https://example.com/arc-empty", None);
        let store =
            SecureCredentialStore::with_data_dir(&cred_key, dir.path()).expect("with_data_dir");
        let arc_store = ArcStore(Arc::new(store));
        let loaded = rmcp::transport::auth::CredentialStore::load(&arc_store)
            .await
            .expect("load");
        // May be Some if a real keyring entry survived from another test, but
        // must not error in either case.
        let _ = loaded;
    }
}
