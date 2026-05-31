//! Build the outbound [`StreamableHttpClientTransport`].
//!
//! Combines:
//!
//! * the user-supplied custom headers (forwarded on every request);
//! * the OAuth-aware HTTP client returned by [`crate::auth`];
//!
//! into a single transport that the rmcp client service can drive.

use std::collections::HashMap;

use anyhow::Result;
use http::{HeaderName, HeaderValue};
use reqwest::Client as HttpClient;
use rmcp::transport::auth::AuthClient;
use rmcp::transport::streamable_http_client::{
    StreamableHttpClientTransport, StreamableHttpClientTransportConfig,
};

use crate::auth::AuthOutcome;

/// A streamable-http client transport, either anonymous or wrapped in
/// rmcp's [`AuthClient`].
///
/// rmcp's `AuthClient` proactively refreshes the access token via
/// `AuthorizationManager::get_access_token()` (which checks expiry against
/// a 30-second buffer) before every request, so we don't add any extra
/// reactive 401-retry layer on top. The handful of edge cases that would
/// slip past that proactive check (token without `expires_in`, clock skew,
/// early server-side revocation) surface as a transport error and let the
/// user `--reset-auth` and relaunch.
///
/// Both variants implement [`rmcp::transport::Transport`] for `RoleClient`,
/// so the proxy can drive either one through the same client service.
pub enum RemoteTransport {
    Anonymous(StreamableHttpClientTransport<HttpClient>),
    Authorized(StreamableHttpClientTransport<AuthClient<HttpClient>>),
}

/// Build the outbound transport for `server_url` from the result of the auth
/// step plus the user-supplied custom header map.
pub fn build(
    server_url: &str,
    headers: HashMap<HeaderName, HeaderValue>,
    auth: AuthOutcome,
) -> Result<RemoteTransport> {
    let config = StreamableHttpClientTransportConfig::with_uri(server_url.to_string())
        .custom_headers(headers);

    Ok(match auth {
        AuthOutcome::Anonymous { http_client } => RemoteTransport::Anonymous(
            StreamableHttpClientTransport::with_client(http_client, config),
        ),
        AuthOutcome::Authorized { client } => {
            RemoteTransport::Authorized(StreamableHttpClientTransport::with_client(client, config))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderName, HeaderValue};

    fn anon_outcome() -> AuthOutcome {
        AuthOutcome::Anonymous {
            http_client: reqwest::Client::new(),
        }
    }

    #[tokio::test]
    async fn build_returns_anonymous_variant_for_anonymous_outcome() {
        let mut headers = HashMap::new();
        headers.insert(
            HeaderName::from_static("x-trace"),
            HeaderValue::from_static("abc"),
        );
        let t = build("https://example.com/mcp", headers, anon_outcome()).expect("build");
        assert!(
            matches!(t, RemoteTransport::Anonymous(_)),
            "anonymous outcome should produce anonymous transport"
        );
    }

    #[tokio::test]
    async fn build_accepts_empty_headers() {
        let t = build("https://example.com/mcp", HashMap::new(), anon_outcome())
            .expect("build with empty headers");
        assert!(matches!(t, RemoteTransport::Anonymous(_)));
    }

    #[tokio::test]
    async fn build_accepts_multiple_headers() {
        let mut headers = HashMap::new();
        headers.insert(
            HeaderName::from_static("x-a"),
            HeaderValue::from_static("1"),
        );
        headers.insert(
            HeaderName::from_static("x-b"),
            HeaderValue::from_static("2"),
        );
        let t = build("http://127.0.0.1:8080/mcp", headers, anon_outcome()).expect("build");
        assert!(matches!(t, RemoteTransport::Anonymous(_)));
    }
}
