//! MCP OAuth discovery (RFC 9728 + RFC 8414).
//!
//! When a Streamable-HTTP MCP server responds with `401 Unauthorized`, it
//! signals that the client must authenticate using the OAuth flow described
//! by the MCP authorization specification. This module performs the discovery
//! half of that flow:
//!
//! 1. Probe the server with a benign request and inspect the response.
//! 2. If it is `401`, parse the `WWW-Authenticate` header for a
//!    `resource_metadata` link and a `scope` parameter (RFC 6750/8414).
//! 3. Fetch the Protected Resource Metadata document (RFC 9728) — either
//!    from the link in the header or from one of the well-known paths.
//! 4. Pick the first listed authorization server and return everything the
//!    caller needs to drive `rmcp`'s `OAuthState`.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde::Deserialize;

/// Outcome of probing the MCP server for OAuth requirements.
#[derive(Debug, Clone)]
pub enum AuthRequirement {
    /// The server accepted an unauthenticated request. No OAuth is needed.
    None,
    /// The server returned `401`. The contained metadata tells us how to
    /// authenticate.
    Required(OAuthDiscovery),
}

/// Information needed to start the OAuth flow against this server.
#[derive(Debug, Clone)]
pub struct OAuthDiscovery {
    /// Issuer URL of the authorization server, as advertised by the
    /// resource's Protected Resource Metadata (or the resource URL itself,
    /// as a fallback — see the comment above). Currently used only for
    /// logging/diagnostics.
    pub authorization_server: String,
    /// Scopes the resource server expects, in priority order:
    /// header scope > PRM scopes_supported. Empty if neither was given.
    pub scopes: Vec<String>,
    /// The MCP resource server's own URL. Defaults to the MCP server URL
    /// passed on the command line (`--resource` overrides it). Used as the
    /// `base_url` for `OAuthState::new`: rmcp's `AuthorizationManager`
    /// treats `base_url` as the resource server, both for validating
    /// Protected Resource Metadata (SEP-985) and as the RFC 8707 `resource`
    /// parameter it attaches to authorize/token/refresh requests. Typed as
    /// a `Url` because rmcp requires a fetchable http(s) URL here — the CLI
    /// layer enforces the scheme before this struct is ever built.
    pub resource: url::Url,
}

/// Protected Resource Metadata, as defined by RFC 9728.
#[derive(Debug, Deserialize)]
struct ProtectedResourceMetadata {
    #[serde(default)]
    authorization_servers: Vec<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
}

/// Probe `server_url` to determine whether OAuth is required, and if so,
/// where to authenticate.
///
/// `headers` are sent on the probe request so e.g. a custom `Authorization`
/// header has a chance to succeed before we conclude OAuth is needed.
pub async fn discover(
    http_client: &reqwest::Client,
    server_url: &str,
    headers: &HashMap<HeaderName, HeaderValue>,
    resource_override: Option<&url::Url>,
) -> Result<AuthRequirement> {
    tracing::debug!(server_url, "probing MCP server for auth requirements");

    let resp = http_client
        .get(server_url)
        .headers(to_header_map(headers))
        .header(http::header::ACCEPT, "application/json, text/event-stream")
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .with_context(|| format!("probe request to {server_url} failed"))?;

    let status = resp.status();
    if status.is_success()
        || status == StatusCode::METHOD_NOT_ALLOWED
        || status == StatusCode::BAD_REQUEST
    {
        // 2xx, 405 (server only takes POST for /mcp), or 400 ("missing
        // session id") all indicate the server is reachable without auth.
        tracing::debug!(%status, "server reachable without auth");
        return Ok(AuthRequirement::None);
    }

    if status != StatusCode::UNAUTHORIZED {
        anyhow::bail!(
            "unexpected response from {server_url}: {status}; refusing to assume OAuth flow"
        );
    }

    // If the user explicitly supplied a static Authorization-style header,
    // they're opting into static-token auth and *not* OAuth. A 401 in that
    // case means their credential was rejected, not that we should silently
    // switch to an OAuth flow they didn't ask for.
    if let Some(name) = supplied_authz_header(headers) {
        let www_auth_hint = resp
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .map(|s| format!("; WWW-Authenticate: {s}"))
            .unwrap_or_default();
        anyhow::bail!(
            "remote MCP server at {server_url} rejected the supplied --header '{name}: ...' with 401 Unauthorized{www_auth_hint}. \
             Refusing to fall back to OAuth because a static credential was provided; \
             check your token or omit the header to use OAuth"
        );
    }

    let www_auth_raw = resp
        .headers()
        .get(http::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let www_auth = www_auth_raw
        .as_deref()
        .map(parse_www_authenticate)
        .unwrap_or_default();

    tracing::debug!(?www_auth, "parsed WWW-Authenticate header");

    let resource = match resource_override {
        Some(r) => r.clone(),
        None => url::Url::parse(server_url).context(
            "server URL is not a valid URL; cannot use it as the OAuth resource identifier",
        )?,
    };

    // Try to fetch Protected Resource Metadata. Order:
    //   1. URL from WWW-Authenticate `resource_metadata=...`
    //   2. <origin>/.well-known/oauth-protected-resource<path>
    //   3. <origin>/.well-known/oauth-protected-resource
    let mut prm_candidates: Vec<String> = Vec::new();
    if let Some(url) = &www_auth.resource_metadata {
        prm_candidates.push(url.clone());
    }
    prm_candidates.extend(well_known_prm_urls(server_url)?);

    let mut prm: Option<ProtectedResourceMetadata> = None;
    for url in &prm_candidates {
        match fetch_prm(http_client, url).await {
            Ok(Some(meta)) => {
                tracing::debug!(prm_url = url, "fetched protected resource metadata");
                prm = Some(meta);
                break;
            }
            Ok(None) => continue,
            Err(e) => {
                tracing::debug!(prm_url = url, error = %e, "PRM fetch failed; trying next");
            }
        }
    }

    let mut scopes = Vec::new();
    if let Some(s) = www_auth.scope.as_ref() {
        scopes.extend(s.split_whitespace().map(str::to_string));
    } else if let Some(meta) = &prm {
        scopes.extend(meta.scopes_supported.iter().cloned());
    }

    // Pick the first authorization server advertised by the PRM document.
    //
    // If PRM didn't give us one, the server's intent depends on whether
    // it sent a `WWW-Authenticate` challenge at all:
    //
    //   * Header present (e.g. `Bearer realm="OAuth", error="..."`) — the
    //     server is explicitly demanding OAuth, it's just not telling us
    //     where. Many real deployments (e.g. mcp.atlassian.com) host
    //     RFC 8414 metadata at the server's origin even though they don't
    //     publish a PRM document or a `resource_metadata=...` link, so we
    //     fall back to using the resource URL itself as the starting
    //     point for RFC 8414 discovery. This matches the behaviour of
    //     the Node `mcp-remote` reference implementation.
    //   * Header absent — we have no signal that OAuth is what's being
    //     asked for. The likely failure mode is a stateful
    //     Streamable-HTTP server returning 401 for a missing
    //     `Mcp-Session-Id` (or similar). Bail with actionable guidance
    //     rather than inventing an authorization server and chasing
    //     OAuth metadata against a non-OAuth server.
    let authorization_server = match prm
        .as_ref()
        .and_then(|m| m.authorization_servers.first().cloned())
    {
        Some(as_url) => as_url,
        None if www_auth_raw.is_some() => {
            tracing::debug!(
                server_url,
                www_authenticate = ?www_auth_raw,
                "401 carries a WWW-Authenticate challenge but no PRM or resource_metadata link; \
                 falling back to server URL for RFC 8414 discovery"
            );
            server_url.to_string()
        }
        None => {
            anyhow::bail!(
                "remote MCP server at {server_url} returned 401 Unauthorized with no \
                 WWW-Authenticate header, and no Protected Resource Metadata document was \
                 discoverable at the well-known endpoints. Refusing to start an OAuth flow \
                 against an unknown authorization server. If this server uses a non-OAuth \
                 auth scheme (e.g. a static bearer token or a stateful `Mcp-Session-Id` \
                 header), re-run with --no-auth (optionally combined with --header to \
                 pass a static credential), or fix the server to emit a spec-compliant \
                 `WWW-Authenticate: Bearer resource_metadata=\"...\"` response"
            );
        }
    };

    Ok(AuthRequirement::Required(OAuthDiscovery {
        authorization_server,
        scopes,
        resource,
    }))
}

/// Returns the well-known PRM URLs to try for `server_url`, in order. RFC
/// 9728 §3.1 prescribes both path-suffixed and root variants.
fn well_known_prm_urls(server_url: &str) -> Result<Vec<String>> {
    let url = url::Url::parse(server_url).context("invalid server URL")?;
    let origin = url.origin().ascii_serialization();
    let path = url.path().trim_end_matches('/');
    let mut out = Vec::with_capacity(2);
    if !path.is_empty() && path != "/" {
        out.push(format!(
            "{origin}/.well-known/oauth-protected-resource{path}"
        ));
    }
    out.push(format!("{origin}/.well-known/oauth-protected-resource"));
    Ok(out)
}

/// Fetch and parse a PRM document. Returns `Ok(None)` on 4xx (treated as
/// "not present"); 5xx or transport errors bubble up.
async fn fetch_prm(
    http_client: &reqwest::Client,
    url: &str,
) -> Result<Option<ProtectedResourceMetadata>> {
    let resp = http_client
        .get(url)
        .header(http::header::ACCEPT, "application/json")
        .timeout(Duration::from_secs(5))
        .send()
        .await?;
    if resp.status().is_client_error() {
        return Ok(None);
    }
    if !resp.status().is_success() {
        anyhow::bail!("PRM fetch returned {}", resp.status());
    }
    let meta: ProtectedResourceMetadata = resp.json().await.context("decoding PRM JSON")?;
    Ok(Some(meta))
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct WwwAuthenticate {
    resource_metadata: Option<String>,
    scope: Option<String>,
}

/// Parse a (Bearer) `WWW-Authenticate` header value, extracting the
/// parameters we care about. Tolerant of slight syntactic deviations.
fn parse_www_authenticate(header: &str) -> WwwAuthenticate {
    let mut out = WwwAuthenticate::default();
    let body = header.trim_start();
    let body = body.strip_prefix("Bearer ").unwrap_or(body);
    let body = body.strip_prefix("bearer ").unwrap_or(body);

    for part in split_top_level(body) {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let value = v.trim().trim_matches('"').to_string();
        match key.as_str() {
            "resource_metadata" => out.resource_metadata = Some(value),
            "scope" => out.scope = Some(value),
            _ => {}
        }
    }
    out
}

/// Split on commas not inside double-quoted strings.
fn split_top_level(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    for (i, ch) in s.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

fn to_header_map(map: &HashMap<HeaderName, HeaderValue>) -> HeaderMap {
    let mut hm = HeaderMap::with_capacity(map.len());
    for (k, v) in map {
        hm.insert(k.clone(), v.clone());
    }
    hm
}

/// If `headers` contains a static `Authorization` or `Proxy-Authorization`
/// header, return its canonical name. Used to detect users who opted into
/// static-token auth and shouldn't be silently rerouted into OAuth on 401.
fn supplied_authz_header(headers: &HashMap<HeaderName, HeaderValue>) -> Option<&'static str> {
    if headers.contains_key(&http::header::AUTHORIZATION) {
        Some("Authorization")
    } else if headers.contains_key(&http::header::PROXY_AUTHORIZATION) {
        Some("Proxy-Authorization")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_www_auth() {
        let h = parse_www_authenticate(
            r#"Bearer error="invalid_request", resource_metadata="https://x/.well-known/foo", scope="read write""#,
        );
        assert_eq!(
            h.resource_metadata.as_deref(),
            Some("https://x/.well-known/foo")
        );
        assert_eq!(h.scope.as_deref(), Some("read write"));
    }

    #[test]
    fn parse_www_auth_without_bearer_prefix() {
        let h = parse_www_authenticate(r#"resource_metadata="https://x/m""#);
        assert_eq!(h.resource_metadata.as_deref(), Some("https://x/m"));
    }

    #[test]
    fn well_known_paths_for_subpath() {
        let urls = well_known_prm_urls("https://example.com/mcp/v1")
            .expect("valid URL must yield PRM candidates");
        assert_eq!(
            urls,
            vec![
                "https://example.com/.well-known/oauth-protected-resource/mcp/v1".to_string(),
                "https://example.com/.well-known/oauth-protected-resource".to_string()
            ]
        );
    }

    #[test]
    fn well_known_paths_for_root() {
        let urls = well_known_prm_urls("https://example.com/")
            .expect("valid URL must yield PRM candidates");
        assert_eq!(
            urls,
            vec!["https://example.com/.well-known/oauth-protected-resource".to_string()]
        );
    }

    #[test]
    fn split_top_level_respects_quotes() {
        let parts = split_top_level(r#"a=1, b="x,y", c=3"#);
        assert_eq!(parts, vec!["a=1", r#" b="x,y""#, " c=3"]);
    }

    #[test]
    fn detects_static_authorization_header() {
        let mut h = HashMap::new();
        h.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer xyz"),
        );
        assert_eq!(supplied_authz_header(&h), Some("Authorization"));
    }

    #[test]
    fn detects_static_proxy_authorization_header() {
        let mut h = HashMap::new();
        h.insert(
            http::header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Bearer xyz"),
        );
        assert_eq!(supplied_authz_header(&h), Some("Proxy-Authorization"));
    }

    #[test]
    fn no_authz_header_returns_none() {
        let mut h = HashMap::new();
        h.insert(
            HeaderName::from_static("x-custom"),
            HeaderValue::from_static("value"),
        );
        assert!(supplied_authz_header(&h).is_none());
    }

    // -- Mock-server-driven `discover()` tests ----------------------------
    //
    // These spin up an axum server on an ephemeral loopback port and assert
    // that `discover()` reaches the right conclusion from each shape of
    // response (anonymous-OK, 401 with no PRM, 401 with PRM, etc).

    use axum::Router;
    use axum::extract::State;
    use axum::http::{HeaderMap as AxumHeaderMap, StatusCode as AxumStatus};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// What the mock should return from `GET /mcp`.
    enum ProbeBehavior {
        Ok,
        MethodNotAllowed,
        BadRequest,
        Unauthorized { www_authenticate: Option<String> },
        ServerError,
    }

    struct MockState {
        probe: ProbeBehavior,
        prm_body: Option<String>,
        /// Counts of which paths we served (PRM discovery exercises
        /// multiple well-known URLs).
        prm_hits: AtomicUsize,
    }

    async fn handle_probe(
        State(state): State<Arc<MockState>>,
        _headers: AxumHeaderMap,
    ) -> axum::response::Response {
        match &state.probe {
            ProbeBehavior::Ok => (AxumStatus::OK, "hello").into_response(),
            ProbeBehavior::MethodNotAllowed => {
                (AxumStatus::METHOD_NOT_ALLOWED, "nope").into_response()
            }
            ProbeBehavior::BadRequest => (AxumStatus::BAD_REQUEST, "bad").into_response(),
            ProbeBehavior::ServerError => {
                (AxumStatus::INTERNAL_SERVER_ERROR, "boom").into_response()
            }
            ProbeBehavior::Unauthorized { www_authenticate } => {
                let mut headers = AxumHeaderMap::new();
                if let Some(v) = www_authenticate {
                    headers.insert("WWW-Authenticate", v.parse().expect("valid header"));
                }
                (AxumStatus::UNAUTHORIZED, headers, "go away").into_response()
            }
        }
    }

    async fn handle_prm(State(state): State<Arc<MockState>>) -> axum::response::Response {
        state.prm_hits.fetch_add(1, Ordering::SeqCst);
        match &state.prm_body {
            Some(body) => (
                AxumStatus::OK,
                [("content-type", "application/json")],
                body.clone(),
            )
                .into_response(),
            None => (AxumStatus::NOT_FOUND, "no prm").into_response(),
        }
    }

    /// Spawn a mock MCP server and return its base URL.
    async fn spawn_mock(state: Arc<MockState>) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route("/mcp", get(handle_probe))
            .route("/.well-known/oauth-protected-resource/mcp", get(handle_prm))
            .route("/.well-known/oauth-protected-resource", get(handle_prm))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        // Give the server a moment to start.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        (format!("http://{addr}"), handle)
    }

    fn empty_headers() -> HashMap<HeaderName, HeaderValue> {
        HashMap::new()
    }

    #[tokio::test]
    async fn discover_returns_none_on_2xx() {
        let state = Arc::new(MockState {
            probe: ProbeBehavior::Ok,
            prm_body: None,
            prm_hits: AtomicUsize::new(0),
        });
        let (base, _h) = spawn_mock(state).await;
        let client = reqwest::Client::new();
        let out = discover(&client, &format!("{base}/mcp"), &empty_headers(), None)
            .await
            .expect("discover");
        assert!(matches!(out, AuthRequirement::None));
    }

    #[tokio::test]
    async fn discover_returns_none_on_405() {
        let state = Arc::new(MockState {
            probe: ProbeBehavior::MethodNotAllowed,
            prm_body: None,
            prm_hits: AtomicUsize::new(0),
        });
        let (base, _h) = spawn_mock(state).await;
        let client = reqwest::Client::new();
        let out = discover(&client, &format!("{base}/mcp"), &empty_headers(), None)
            .await
            .expect("discover");
        assert!(matches!(out, AuthRequirement::None));
    }

    #[tokio::test]
    async fn discover_returns_none_on_400() {
        let state = Arc::new(MockState {
            probe: ProbeBehavior::BadRequest,
            prm_body: None,
            prm_hits: AtomicUsize::new(0),
        });
        let (base, _h) = spawn_mock(state).await;
        let client = reqwest::Client::new();
        let out = discover(&client, &format!("{base}/mcp"), &empty_headers(), None)
            .await
            .expect("discover");
        assert!(matches!(out, AuthRequirement::None));
    }

    #[tokio::test]
    async fn discover_errors_on_5xx() {
        let state = Arc::new(MockState {
            probe: ProbeBehavior::ServerError,
            prm_body: None,
            prm_hits: AtomicUsize::new(0),
        });
        let (base, _h) = spawn_mock(state).await;
        let client = reqwest::Client::new();
        let err = discover(&client, &format!("{base}/mcp"), &empty_headers(), None)
            .await
            .expect_err("5xx must not be silently treated as anonymous-OK");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("unexpected response") || msg.contains("500"),
            "got: {msg}"
        );
    }

    #[tokio::test]
    async fn discover_bails_when_static_authz_header_rejected() {
        let state = Arc::new(MockState {
            probe: ProbeBehavior::Unauthorized {
                www_authenticate: Some("Bearer error=\"invalid_token\"".to_string()),
            },
            prm_body: None,
            prm_hits: AtomicUsize::new(0),
        });
        let (base, _h) = spawn_mock(state).await;

        let mut headers = HashMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer not-real"),
        );

        let client = reqwest::Client::new();
        let err = discover(&client, &format!("{base}/mcp"), &headers, None)
            .await
            .expect_err("static-credential 401 must not silently switch to OAuth");
        let msg = format!("{err:#}");
        assert!(msg.contains("Authorization"), "got: {msg}");
        assert!(msg.contains("401"), "got: {msg}");
    }

    #[tokio::test]
    async fn discover_resolves_oauth_requirement_from_prm() {
        let prm = serde_json::json!({
            "authorization_servers": ["https://auth.example.com"],
            "scopes_supported": ["read", "write"],
        })
        .to_string();
        let state = Arc::new(MockState {
            probe: ProbeBehavior::Unauthorized {
                www_authenticate: None,
            },
            prm_body: Some(prm),
            prm_hits: AtomicUsize::new(0),
        });
        let (base, _h) = spawn_mock(state).await;

        let client = reqwest::Client::new();
        let out = discover(&client, &format!("{base}/mcp"), &empty_headers(), None)
            .await
            .expect("discover");
        match out {
            AuthRequirement::Required(d) => {
                assert_eq!(d.authorization_server, "https://auth.example.com");
                assert_eq!(d.scopes, vec!["read".to_string(), "write".to_string()]);
                assert_eq!(
                    d.resource.as_str(),
                    format!("{base}/mcp"),
                    "without --resource, the resource must default to the server URL"
                );
            }
            AuthRequirement::None => panic!("expected Required, got None"),
        }
    }

    #[tokio::test]
    async fn discover_prefers_www_authenticate_scope_over_prm() {
        let prm = serde_json::json!({
            "authorization_servers": ["https://auth.example.com"],
            "scopes_supported": ["prm-only"],
        })
        .to_string();
        let state = Arc::new(MockState {
            probe: ProbeBehavior::Unauthorized {
                www_authenticate: Some(r#"Bearer scope="header-a header-b""#.to_string()),
            },
            prm_body: Some(prm),
            prm_hits: AtomicUsize::new(0),
        });
        let (base, _h) = spawn_mock(state).await;

        let override_url = url::Url::parse("https://tenant.example.com/mcp").expect("override URL");
        let client = reqwest::Client::new();
        let out = discover(
            &client,
            &format!("{base}/mcp"),
            &empty_headers(),
            Some(&override_url),
        )
        .await
        .expect("discover");
        match out {
            AuthRequirement::Required(d) => {
                assert_eq!(
                    d.scopes,
                    vec!["header-a".to_string(), "header-b".to_string()],
                    "header scope must win over PRM scopes_supported"
                );
                assert_eq!(d.resource, override_url);
            }
            AuthRequirement::None => panic!("expected Required"),
        }
    }

    #[tokio::test]
    async fn discover_skips_oauth_when_static_authorization_is_accepted() {
        // Spin up a mock that *requires* a static `Authorization: Bearer ...`
        // header on the probe: requests without it get 401, requests with
        // the expected value get 200. This proves two things at once:
        //   1. discover() forwards user-supplied --header values on the
        //      probe request (otherwise the mock would 401 and we'd bail).
        //   2. A 2xx probe short-circuits to `AuthRequirement::None`, so
        //      no PRM lookup, no OAuth state machine, no browser.
        async fn gated(headers: AxumHeaderMap) -> axum::response::Response {
            match headers.get("authorization").and_then(|v| v.to_str().ok()) {
                Some("Bearer good-token") => (AxumStatus::OK, "ok").into_response(),
                _ => (AxumStatus::UNAUTHORIZED, "need bearer").into_response(),
            }
        }

        let app = Router::new().route("/mcp", get(gated));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let _h = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let server_url = format!("http://{addr}/mcp");

        let mut headers = HashMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer good-token"),
        );

        let client = reqwest::Client::new();
        let out = discover(&client, &server_url, &headers, None)
            .await
            .expect("discover");
        assert!(
            matches!(out, AuthRequirement::None),
            "static Authorization accepted by server must short-circuit to None (no OAuth)"
        );
    }

    #[tokio::test]
    async fn discover_falls_back_to_server_url_when_www_authenticate_has_no_resource_metadata() {
        // Atlassian-style: server returns 401 with a clear `Bearer` challenge
        // (so it's OAuth-shaped) but no `resource_metadata=` parameter and no
        // discoverable PRM document. The previous over-strict bail regressed
        // this case; the right behaviour is to fall back to using the
        // resource URL itself as the AS starting point and let rmcp's
        // RFC 8414 discovery find the metadata at the server's origin.
        let state = Arc::new(MockState {
            probe: ProbeBehavior::Unauthorized {
                www_authenticate: Some(
                    "Bearer realm=\"OAuth\", error=\"invalid_token\", \
                     error_description=\"Missing or invalid access token\""
                        .to_string(),
                ),
            },
            prm_body: None, // 404 on PRM endpoints
            prm_hits: AtomicUsize::new(0),
        });
        let (base, _h) = spawn_mock(state).await;
        let server_url = format!("{base}/mcp");

        let client = reqwest::Client::new();
        let out = discover(&client, &server_url, &empty_headers(), None)
            .await
            .expect("discover must NOT bail when a Bearer challenge is present");
        match out {
            AuthRequirement::Required(d) => {
                assert_eq!(
                    d.authorization_server, server_url,
                    "with a Bearer challenge but no resource_metadata/PRM, fall back to \
                     the resource URL as the AS so RFC 8414 discovery can find metadata at \
                     the server's origin"
                );
            }
            AuthRequirement::None => panic!("expected Required, got None"),
        }
    }

    #[tokio::test]
    async fn discover_bails_on_401_without_www_authenticate_or_prm() {
        // Regression: a server that returns a bare 401 with neither a
        // WWW-Authenticate header nor a discoverable PRM document gives us
        // no actionable authorization-server URL. Previous behaviour was to
        // silently treat the resource URL itself as the authorization
        // server, which sent us chasing OAuth metadata against servers
        // that don't speak OAuth at all (e.g. stateful Streamable-HTTP
        // servers that 401 on a missing `Mcp-Session-Id` header).
        let state = Arc::new(MockState {
            probe: ProbeBehavior::Unauthorized {
                www_authenticate: None,
            },
            prm_body: None, // 404 on PRM endpoints
            prm_hits: AtomicUsize::new(0),
        });
        let (base, _h) = spawn_mock(state).await;
        let server_url = format!("{base}/mcp");

        let client = reqwest::Client::new();
        let err = discover(&client, &server_url, &empty_headers(), None)
            .await
            .expect_err("must refuse to invent an authorization server");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no WWW-Authenticate header"),
            "error should explain the missing OAuth signal; got: {msg}"
        );
        assert!(
            msg.contains("Mcp-Session-Id") || msg.contains("WWW-Authenticate"),
            "error should hint at common causes; got: {msg}"
        );
        assert!(
            msg.contains("--no-auth"),
            "error should point users at the --no-auth escape hatch; got: {msg}"
        );
    }
}
