//! Local HTTP server that receives the OAuth authorization-code redirect.
//!
//! Spins up an axum server on `127.0.0.1:<port>` (port auto-selected if zero),
//! exposes a single `GET /oauth/callback` route, and resolves a oneshot
//! channel with the `(code, state)` pair as soon as the browser hits it.
//!
//! The server shuts itself down after the first successful callback.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use serde::Deserialize;
use tokio::sync::{Mutex, oneshot};
use tokio_util::sync::CancellationToken;

/// Path the authorization server will redirect to.
pub const CALLBACK_PATH: &str = "/oauth/callback";

/// The result of a successful OAuth callback.
#[derive(Debug, Clone)]
pub struct AuthCode {
    pub code: String,
    pub state: String,
    /// RFC 9207 authorization server issuer identifier, if the server sent
    /// one. Must be forwarded to rmcp's issuer-checking callback handler —
    /// servers that advertise `authorization_response_iss_parameter_supported`
    /// hard-require it back at token-exchange time.
    pub iss: Option<String>,
}

/// A running callback server. Drop the handle to shut it down early; call
/// [`Self::wait`] to wait for the code or a timeout.
pub struct CallbackServer {
    /// `http://host:port/oauth/callback` to register as the OAuth redirect.
    pub redirect_uri: String,
    /// Background task running the server.
    server_task: tokio::task::JoinHandle<()>,
    /// One-shot receiver delivering the first valid callback.
    code_rx: oneshot::Receiver<Result<AuthCode, CallbackError>>,
    /// Cancellation token used to shut the server down.
    cancel: CancellationToken,
}

#[derive(Debug, thiserror::Error)]
pub enum CallbackError {
    #[error("authorization server returned error: {error}{}", description.as_deref().map(|d| format!(" ({d})")).unwrap_or_default())]
    AuthServer {
        error: String,
        description: Option<String>,
    },
    #[error("callback did not include an authorization code")]
    MissingCode,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    iss: Option<String>,
}

struct AppState {
    /// Wrapped in Mutex<Option<>> because the axum handler needs `&` access
    /// and the sender can only be consumed once.
    code_tx: Mutex<Option<oneshot::Sender<Result<AuthCode, CallbackError>>>>,
    cancel: CancellationToken,
}

impl CallbackServer {
    /// Bind a callback server on `host:port` (port=0 picks an ephemeral one)
    /// and start serving immediately.
    pub async fn bind(host: &str, port: u16) -> Result<Self> {
        let host: IpAddr = host
            .parse()
            .with_context(|| format!("invalid callback host '{host}'"))?;
        let addr = SocketAddr::new(host, port);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind OAuth callback server to {addr}"))?;
        let actual_addr = listener.local_addr()?;

        let (code_tx, code_rx) = oneshot::channel();
        let cancel = CancellationToken::new();

        let state = Arc::new(AppState {
            code_tx: Mutex::new(Some(code_tx)),
            cancel: cancel.clone(),
        });

        let app = Router::new()
            .route(CALLBACK_PATH, get(handle_callback))
            .with_state(state);

        let shutdown_cancel = cancel.clone();
        let server_task = tokio::spawn(async move {
            let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
                shutdown_cancel.cancelled().await;
            });
            if let Err(e) = serve.await {
                tracing::warn!(error = %e, "OAuth callback server exited with error");
            }
        });

        let redirect_uri = format!("http://{}{CALLBACK_PATH}", actual_addr);
        tracing::info!(redirect_uri, "OAuth callback server listening");

        Ok(Self {
            redirect_uri,
            server_task,
            code_rx,
            cancel,
        })
    }

    /// Wait up to `timeout` for the browser to hit the callback URL.
    pub async fn wait(self, timeout: Duration) -> Result<AuthCode> {
        let Self {
            server_task,
            code_rx,
            cancel,
            ..
        } = self;

        let result = tokio::time::timeout(timeout, code_rx).await;
        // We always want to shut the server down once we have an answer
        // (success, error, or timeout).
        cancel.cancel();
        let _ = server_task.await;

        match result {
            Ok(Ok(Ok(code))) => Ok(code),
            Ok(Ok(Err(e))) => Err(anyhow::Error::new(e)),
            Ok(Err(_)) => anyhow::bail!("OAuth callback channel dropped before receiving a code"),
            Err(_) => anyhow::bail!(
                "timed out after {}s waiting for OAuth callback; the user did not complete the authorization flow",
                timeout.as_secs()
            ),
        }
    }
}

async fn handle_callback(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CallbackQuery>,
) -> Html<&'static str> {
    let result = if let Some(error) = q.error {
        Err(CallbackError::AuthServer {
            error,
            description: q.error_description,
        })
    } else if let (Some(code), Some(state)) = (q.code, q.state) {
        Ok(AuthCode {
            code,
            state,
            iss: q.iss,
        })
    } else {
        Err(CallbackError::MissingCode)
    };

    let is_ok = result.is_ok();

    if let Some(tx) = state.code_tx.lock().await.take() {
        let _ = tx.send(result);
    }
    // Trigger graceful shutdown after the response has been sent.
    let cancel = state.cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
    });

    if is_ok {
        Html(SUCCESS_HTML)
    } else {
        Html(FAILURE_HTML)
    }
}

const SUCCESS_HTML: &str = r#"<!doctype html>
<html><head><title>Authorization complete</title>
<style>body{font-family:system-ui,sans-serif;margin:4em auto;max-width:32em;text-align:center}</style>
</head><body>
<h1>✅ Authorization complete</h1>
<p>You can close this tab and return to your MCP client.</p>
<script>setTimeout(()=>window.close(),500);</script>
</body></html>"#;

const FAILURE_HTML: &str = r#"<!doctype html>
<html><head><title>Authorization failed</title>
<style>body{font-family:system-ui,sans-serif;margin:4em auto;max-width:32em;text-align:center;color:#900}</style>
</head><body>
<h1>❌ Authorization failed</h1>
<p>Check the proxy's stderr for details, then try again.</p>
</body></html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// Pull the listening port out of a `http://host:port/oauth/callback` URI.
    fn port_from(uri: &str) -> u16 {
        let url = url::Url::parse(uri).expect("valid redirect_uri");
        url.port().expect("redirect_uri must include port")
    }

    #[tokio::test]
    async fn bind_picks_ephemeral_port_when_zero() {
        let server = CallbackServer::bind("127.0.0.1", 0)
            .await
            .expect("bind on ephemeral port");
        assert!(server.redirect_uri.starts_with("http://127.0.0.1:"));
        assert!(server.redirect_uri.ends_with(CALLBACK_PATH));
        assert!(
            port_from(&server.redirect_uri) > 0,
            "ephemeral port must be allocated"
        );
        // Cancel cleanly so the background task winds down.
        server.cancel.cancel();
        let _ = server.server_task.await;
    }

    #[tokio::test]
    async fn bind_rejects_invalid_host() {
        match CallbackServer::bind("not-an-ip", 0).await {
            Ok(_) => panic!("non-IP host must be rejected"),
            Err(err) => assert!(err.to_string().contains("invalid callback host")),
        }
    }

    #[tokio::test]
    async fn successful_callback_yields_code_and_state() {
        let server = CallbackServer::bind("127.0.0.1", 0).await.expect("bind");
        let url = format!("{}?code=abc123&state=xyz789", server.redirect_uri);

        // Drive the server to completion by polling the callback URL
        // concurrently with the wait future.
        let client = reqwest::Client::new();
        let waiter = tokio::spawn(server.wait(Duration::from_secs(5)));

        let resp = client.get(&url).send().await.expect("send");
        assert!(resp.status().is_success());
        let body = resp.text().await.expect("body");
        assert!(body.contains("Authorization complete"));

        let code = waiter.await.expect("task").expect("wait");
        assert_eq!(code.code, "abc123");
        assert_eq!(code.state, "xyz789");
        assert_eq!(
            code.iss, None,
            "no iss param sent means AuthCode.iss must be None, not an empty string or default"
        );
    }

    /// Regression test: `iss` (RFC 9207) must be captured and threaded
    /// through to `AuthCode`, not silently dropped. Authorization servers
    /// that advertise `authorization_response_iss_parameter_supported` (e.g.
    /// Cloudflare's) hard-require this value back at token-exchange time via
    /// `handle_callback_with_issuer`; losing it here made every such server
    /// fail authorization with "response missing required issuer".
    #[tokio::test]
    async fn callback_with_iss_param_is_captured() {
        let server = CallbackServer::bind("127.0.0.1", 0).await.expect("bind");
        let url = format!(
            "{}?code=abc123&state=xyz789&iss=https%3A%2F%2Fauth.example.com",
            server.redirect_uri
        );

        let client = reqwest::Client::new();
        let waiter = tokio::spawn(server.wait(Duration::from_secs(5)));

        let resp = client.get(&url).send().await.expect("send");
        assert!(resp.status().is_success());

        let code = waiter.await.expect("task").expect("wait");
        assert_eq!(code.iss.as_deref(), Some("https://auth.example.com"));
    }

    #[tokio::test]
    async fn callback_with_error_propagates() {
        let server = CallbackServer::bind("127.0.0.1", 0).await.expect("bind");
        let url = format!(
            "{}?error=access_denied&error_description=user+said+no",
            server.redirect_uri
        );

        let client = reqwest::Client::new();
        let waiter = tokio::spawn(server.wait(Duration::from_secs(5)));

        let resp = client.get(&url).send().await.expect("send");
        assert!(resp.status().is_success());
        let body = resp.text().await.expect("body");
        assert!(body.contains("Authorization failed"));

        let err = waiter
            .await
            .expect("task")
            .expect_err("error param must surface");
        let msg = err.to_string();
        assert!(msg.contains("access_denied"), "got: {msg}");
        assert!(msg.contains("user said no"), "got: {msg}");
    }

    #[tokio::test]
    async fn callback_without_code_returns_missing_code() {
        let server = CallbackServer::bind("127.0.0.1", 0).await.expect("bind");
        // No `code` and no `error` — missing parameters.
        let url = server.redirect_uri.clone();

        let client = reqwest::Client::new();
        let waiter = tokio::spawn(server.wait(Duration::from_secs(5)));

        let resp = client.get(&url).send().await.expect("send");
        assert!(resp.status().is_success());

        let err = waiter
            .await
            .expect("task")
            .expect_err("missing code must surface as error");
        assert!(err.to_string().contains("authorization code"));
    }

    #[tokio::test]
    async fn wait_times_out_when_no_callback_received() {
        let server = CallbackServer::bind("127.0.0.1", 0).await.expect("bind");
        let err = server
            .wait(Duration::from_millis(150))
            .await
            .expect_err("wait must time out");
        assert!(err.to_string().contains("timed out"));
    }
}
