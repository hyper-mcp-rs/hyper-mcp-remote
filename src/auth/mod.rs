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

    // 2. Try cached credentials first. On a cache miss — or a cache whose
    //    access AND refresh tokens are both dead — fall through to the
    //    interactive flow instead of bailing: many MCP hosts never restart
    //    a failed server process, so exiting here would strand the user
    //    with a dead connection until they manually relaunched.
    let state = match try_cached_credentials(&store, &discovery).await? {
        Some(state) => state,
        None => {
            // 3. Full interactive flow on a fresh `OAuthState`. Fresh for
            // two reasons: a state that has been through `set_credentials`
            // is `Authorized`, and `start_authorization` requires
            // `Unauthorized`; and starting over redoes dynamic client
            // registration — when a refresh token is dead the server may
            // well have pruned the client registration along with it, so
            // the cached `client_id` can't be trusted either.
            let mut state = new_oauth_state(&discovery, &store).await?;
            run_interactive_flow(cli, &mut state, &discovery)
                .await
                .context("interactive OAuth flow failed")?;
            state
        }
    };

    Ok(AuthOutcome::Authorized {
        client: into_auth_client(state, http_client)?,
    })
}

/// Construct an `Unauthorized` [`OAuthState`] wired to our credential store.
///
/// We deliberately pass `None` for the HTTP client so that rmcp builds its
/// own internal client for talking to the authorization server. rmcp's auth
/// module depends on a different (older) major of `reqwest` than the
/// streamable-http transport, and mixing the two would require
/// hand-bridging incompatible client types.
async fn new_oauth_state(
    discovery: &OAuthDiscovery,
    store: &Arc<SecureCredentialStore>,
) -> Result<OAuthState> {
    let mut state = OAuthState::new(discovery.authorization_server.as_str(), None)
        .await
        .context("failed to initialize OAuth state machine")?;
    install_credential_store(&mut state, store.clone()).await?;
    Ok(state)
}

/// Attempt to build an `Authorized` [`OAuthState`] from cached credentials.
///
/// Returns:
/// - `Ok(Some(state))` — cached credentials are usable (proactively
///   refreshed first if the access token was stale).
/// - `Ok(None)` — nothing usable is cached, or the cached tokens were
///   expired and the refresh exchange failed. In the latter case the cache
///   has been cleared so the caller can run a clean interactive flow.
/// - `Err(_)` — infrastructure failure (credential store I/O, OAuth state
///   machine construction).
async fn try_cached_credentials(
    store: &Arc<SecureCredentialStore>,
    discovery: &OAuthDiscovery,
) -> Result<Option<OAuthState>> {
    let Some(cached) = store
        .as_ref()
        .load_via_trait()
        .await
        .context("failed to load cached credentials")?
    else {
        return Ok(None);
    };
    let Some(token) = cached.token_response.clone() else {
        return Ok(None);
    };

    let mut state = new_oauth_state(discovery, store).await?;

    // Detect staleness BEFORE handing the token to rmcp.
    // `OAuthState::set_credentials` unconditionally overwrites
    // `token_received_at` with the current time when it persists the
    // restored credentials (see rmcp 1.7 transport/auth.rs L2325), so
    // by the time we'd ask `get_access_token` it would compute
    // `elapsed = 0` and treat an actually-expired token as fresh.
    // We have to make the expiry call ourselves, using the genuine
    // `token_received_at` we just loaded.
    let stale = cached_access_token_is_stale(&cached);
    tracing::info!(
        stale_cached_token = stale,
        token_received_at = ?cached.token_received_at,
        "found cached OAuth credentials; using them"
    );
    state
        .set_credentials(&cached.client_id, token)
        .await
        .context("failed to apply cached credentials")?;

    // `set_credentials` just clobbered `token_received_at` on disk
    // with the current time. That would lie to every future launch
    // (this one observed the lie when investigating the GitLab cache
    // failure: the genuine timestamp was overwritten on a previous
    // run, making an expired access token look fresh forever). Write
    // the original `StoredCredentials` back so the next launch sees
    // the truth.
    if let Err(e) = store.as_ref().save_via_trait(cached.clone()).await {
        tracing::warn!(
            error = %e,
            "could not restore genuine token_received_at after set_credentials; \
             future launches may incorrectly treat an expired token as fresh"
        );
    }

    if stale {
        // We're now in `Authorized` with the wrong `received_at`.
        // Force a refresh so the cache (and the in-memory token rmcp
        // will hand to the transport) reflect a genuinely-fresh
        // access token. If the refresh fails because the refresh
        // token itself is no good, wipe the cache and signal the
        // caller to run a clean interactive flow in this same process.
        tracing::info!("cached access token is expired or within refresh buffer; refreshing now");
        match state.refresh_token().await {
            Ok(()) => tracing::info!("refresh succeeded; cached credentials are current"),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not refresh expired cached credentials; clearing cache \
                     and falling back to interactive re-authorization"
                );
                if let Err(clear_err) = store.clear_sync() {
                    tracing::warn!(
                        error = %clear_err,
                        "failed to clear stale credential cache"
                    );
                }
                return Ok(None);
            }
        }
    }

    Ok(Some(state))
}

/// Convenience method on the concrete `SecureCredentialStore` that mirrors
/// `CredentialStore::load` but doesn't require importing the trait at the
/// call site.
#[async_trait::async_trait]
trait CredentialStoreExt {
    async fn load_via_trait(
        &self,
    ) -> Result<Option<rmcp::transport::auth::StoredCredentials>, rmcp::transport::auth::AuthError>;

    async fn save_via_trait(
        &self,
        creds: rmcp::transport::auth::StoredCredentials,
    ) -> Result<(), rmcp::transport::auth::AuthError>;
}

#[async_trait::async_trait]
impl CredentialStoreExt for SecureCredentialStore {
    async fn load_via_trait(
        &self,
    ) -> Result<Option<rmcp::transport::auth::StoredCredentials>, rmcp::transport::auth::AuthError>
    {
        <Self as rmcp::transport::auth::CredentialStore>::load(self).await
    }

    async fn save_via_trait(
        &self,
        creds: rmcp::transport::auth::StoredCredentials,
    ) -> Result<(), rmcp::transport::auth::AuthError> {
        <Self as rmcp::transport::auth::CredentialStore>::save(self, creds).await
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
    tracing::warn!("\nOpen this URL in your browser to authorize hyper-mcp-remote:\n{auth_url}\n");
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

/// Number of seconds before nominal expiry at which we treat a cached
/// access token as effectively expired and trigger a proactive refresh.
/// Mirrors `AuthorizationManager::REFRESH_BUFFER_SECS` in rmcp so that the
/// two checks agree on what "about to expire" means.
const REFRESH_BUFFER_SECS: u64 = 30;

/// True if the cached access token has expired, or is within
/// [`REFRESH_BUFFER_SECS`] of expiring, according to the genuine
/// `token_received_at` from our credential store. Returns `false` when
/// the cache lacks the information needed to make the call (no
/// `token_received_at`, no `expires_in`, missing `token_response`) so we
/// don't refresh-storm caches that pre-date timestamping.
fn cached_access_token_is_stale(cached: &rmcp::transport::auth::StoredCredentials) -> bool {
    use oauth2::TokenResponse;

    let Some(received_at) = cached.token_received_at else {
        return false;
    };
    let Some(token) = cached.token_response.as_ref() else {
        return false;
    };
    let Some(expires_in) = token.expires_in() else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let elapsed = now.saturating_sub(received_at);
    expires_in.as_secs().saturating_sub(elapsed) < REFRESH_BUFFER_SECS
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

    // -- cached_access_token_is_stale -----------------------------------

    fn sample_stored(
        token_received_at: Option<u64>,
        expires_in_secs: Option<u64>,
    ) -> rmcp::transport::auth::StoredCredentials {
        // Build a StoredCredentials via JSON to avoid pulling in oauth2's
        // builder API just to construct one; this mirrors what rmcp itself
        // writes to disk.
        let mut token = serde_json::json!({
            "access_token": "cached-access",
            "token_type": "bearer",
            "refresh_token": "cached-refresh",
        });
        if let Some(secs) = expires_in_secs {
            token["expires_in"] = serde_json::Value::from(secs);
        }
        let stored = serde_json::json!({
            "client_id": "client-abc",
            "token_response": token,
            "granted_scopes": [],
            "token_received_at": token_received_at,
        });
        serde_json::from_value(stored).expect("sample StoredCredentials must deserialize")
    }

    fn now_epoch_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs()
    }

    #[test]
    fn stale_when_received_long_ago_with_short_expiry() {
        // Token received 2 hours ago, expires_in=3600 -> expired by an hour.
        let stored = sample_stored(Some(now_epoch_secs() - 7200), Some(3600));
        assert!(
            cached_access_token_is_stale(&stored),
            "a 1h token received 2h ago must be flagged stale"
        );
    }

    #[test]
    fn stale_when_within_refresh_buffer() {
        // Token expires in REFRESH_BUFFER_SECS - 1 seconds: still nominally
        // valid but inside the proactive-refresh window.
        let stored = sample_stored(
            Some(now_epoch_secs() - (3600 - (REFRESH_BUFFER_SECS - 1))),
            Some(3600),
        );
        assert!(
            cached_access_token_is_stale(&stored),
            "token within REFRESH_BUFFER_SECS of expiry must be flagged stale"
        );
    }

    #[test]
    fn fresh_when_well_inside_validity_window() {
        let stored = sample_stored(Some(now_epoch_secs() - 60), Some(3600));
        assert!(
            !cached_access_token_is_stale(&stored),
            "a 1h token received 1min ago must be fresh"
        );
    }

    #[test]
    fn fresh_when_no_received_at_to_compare_against() {
        // Legacy cache entries written before token_received_at was tracked
        // must NOT be eagerly refreshed; that would refresh-storm on every
        // launch for users with old caches.
        let stored = sample_stored(None, Some(3600));
        assert!(!cached_access_token_is_stale(&stored));
    }

    #[test]
    fn fresh_when_no_expires_in_to_compare_against() {
        // A token without expires_in is treated as non-expiring as far as
        // proactive refresh is concerned; the server is the source of
        // truth and a reactive 401 will surface as a transport error.
        let stored = sample_stored(Some(now_epoch_secs() - 86_400), None);
        assert!(!cached_access_token_is_stale(&stored));
    }

    // --------------------------------------------------------------------

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

    // -- try_cached_credentials -------------------------------------------

    use axum::http::StatusCode;
    use axum::routing::post;

    /// Minimal OAuth authorization server: serves RFC 8414 metadata (which
    /// rmcp's `set_credentials` fetches) and a token endpoint that either
    /// grants refresh exchanges or rejects them with `invalid_grant`,
    /// depending on `refresh_ok`.
    async fn spawn_mock_auth_server(refresh_ok: bool) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let base = format!("http://{addr}");

        let metadata = serde_json::json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
        });
        let token_reply = if refresh_ok {
            (
                StatusCode::OK,
                serde_json::json!({
                    "access_token": "refreshed-access",
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "refresh_token": "refreshed-refresh",
                }),
            )
        } else {
            (
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": "invalid_grant",
                    "error_description": "refresh token revoked or expired",
                }),
            )
        };

        let app = Router::new()
            .route(
                "/.well-known/oauth-authorization-server",
                get(move || {
                    let metadata = metadata.clone();
                    async move { axum::Json(metadata) }
                }),
            )
            .route(
                "/token",
                post(move || {
                    let (status, body) = token_reply.clone();
                    async move { (status, axum::Json(body)) }
                }),
            );

        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        (base, handle)
    }

    fn mock_discovery(auth_server: &str) -> OAuthDiscovery {
        OAuthDiscovery {
            authorization_server: auth_server.to_string(),
            scopes: vec![],
            resource: "https://example.com/mcp".to_string(),
        }
    }

    fn make_test_store(dir: &std::path::Path, salt: &str) -> Arc<SecureCredentialStore> {
        let key = CredentialKey::new(&format!("https://example.com/{salt}"), None);
        let store = SecureCredentialStore::with_data_dir(&key, dir).expect("with_data_dir");
        // Clear any leftover keyring entry from previous runs so tests are
        // deterministic on machines with a real keyring.
        store.clear_sync().expect("clear_sync");
        Arc::new(store)
    }

    #[tokio::test]
    async fn try_cached_credentials_returns_none_on_empty_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = make_test_store(dir.path(), "tcc-empty");
        // Point at an unbound port: an empty cache must short-circuit
        // before any network I/O happens.
        let discovery = mock_discovery("http://127.0.0.1:1");

        let out = try_cached_credentials(&store, &discovery)
            .await
            .expect("empty cache is not an error");
        assert!(
            out.is_none(),
            "empty cache must signal interactive fallback"
        );
    }

    #[tokio::test]
    async fn try_cached_credentials_accepts_fresh_cache_and_preserves_timestamp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = make_test_store(dir.path(), "tcc-fresh");
        // refresh_ok = false: if the fresh-token path ever hit the token
        // endpoint, the mock would reject it and the assertions would fail.
        let (auth_url, _h) = spawn_mock_auth_server(false).await;

        let received_at = now_epoch_secs() - 60;
        store
            .save_via_trait(sample_stored(Some(received_at), Some(3600)))
            .await
            .expect("save");

        let out = try_cached_credentials(&store, &mock_discovery(&auth_url))
            .await
            .expect("fresh cache must not error");
        let state = out.expect("fresh cached creds must be usable without refresh");
        assert!(
            state.into_authorization_manager().is_some(),
            "returned state must be Authorized"
        );

        let stored = store
            .load_via_trait()
            .await
            .expect("load")
            .expect("creds must still be cached");
        assert_eq!(
            stored.token_received_at,
            Some(received_at),
            "genuine token_received_at must survive set_credentials"
        );
        store.clear_sync().expect("cleanup");
    }

    #[tokio::test]
    async fn try_cached_credentials_refreshes_stale_cache() {
        use oauth2::TokenResponse;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = make_test_store(dir.path(), "tcc-stale-refresh");
        let (auth_url, _h) = spawn_mock_auth_server(true).await;

        // Received 2h ago with a 1h lifetime: expired, must trigger refresh.
        store
            .save_via_trait(sample_stored(Some(now_epoch_secs() - 7200), Some(3600)))
            .await
            .expect("save");

        let out = try_cached_credentials(&store, &mock_discovery(&auth_url))
            .await
            .expect("refreshable stale cache must not error");
        let state = out.expect("stale-but-refreshable creds must be usable");
        assert!(
            state.into_authorization_manager().is_some(),
            "returned state must be Authorized"
        );

        let stored = store
            .load_via_trait()
            .await
            .expect("load")
            .expect("refreshed creds must be cached");
        let token = stored.token_response.expect("token_response present");
        assert_eq!(
            token.access_token().secret(),
            "refreshed-access",
            "cache must hold the refreshed access token"
        );
        assert!(
            stored.token_received_at.unwrap_or(0) >= now_epoch_secs() - 60,
            "token_received_at must reflect the fresh exchange"
        );
        store.clear_sync().expect("cleanup");
    }

    #[tokio::test]
    async fn try_cached_credentials_falls_back_and_clears_cache_when_refresh_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = make_test_store(dir.path(), "tcc-dead-refresh");
        let (auth_url, _h) = spawn_mock_auth_server(false).await;

        // Both tokens dead: access token expired, refresh exchange rejected.
        store
            .save_via_trait(sample_stored(Some(now_epoch_secs() - 7200), Some(3600)))
            .await
            .expect("save");

        let out = try_cached_credentials(&store, &mock_discovery(&auth_url))
            .await
            .expect("a dead refresh token must NOT be fatal");
        assert!(
            out.is_none(),
            "dead refresh token must signal interactive fallback"
        );
        assert!(
            store.load_via_trait().await.expect("load").is_none(),
            "cache must be cleared so the interactive flow starts clean"
        );
    }
}
