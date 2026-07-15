//! End-to-end integration test against the real GitLab MCP server at
//! `https://gitlab.com/api/v4/mcp`.
//!
//! This spawns the compiled `hyper-mcp-remote` binary as a child process —
//! exactly the way an MCP client (Claude Desktop, Cursor, Zed, …) would —
//! and drives `initialize` + `tools/list` through it via the child's
//! stdin/stdout. The proxy in turn performs the MCP OAuth flow against
//! GitLab and forwards the JSON-RPC traffic over Streamable-HTTP.
//!
//! ```text
//! test harness ──stdio (TokioChildProcess)──▶ hyper-mcp-remote ──HTTPS+OAuth──▶ gitlab.com
//! ```
//!
//! ## Why `#[ignore]`?
//!
//! The first run of this test will open a browser window for the user to
//! complete the OAuth consent flow against GitLab — there is no headless
//! way to do this without baking real credentials into the test. Subsequent
//! runs reuse the refresh token cached in the OS keyring (or the file
//! fallback under the user's data directory). Either way the test:
//!
//!   * hits the public internet,
//!   * requires gitlab.com to be reachable,
//!   * may require human interaction on first run.
//!
//! So it's gated behind `#[ignore]` and CI never runs it.
//!
//! ## Manual run
//!
//! ```sh
//! cargo test --test e2e_gitlab -- --ignored --nocapture
//! ```
//!
//! `--nocapture` is important because the proxy prints the authorization
//! URL to its own stderr; without `--nocapture` you won't see it.
//!
//! ## Manually validating dead-token recovery
//!
//! The unit tests in `src/auth/mod.rs` cover the "access token expired AND
//! refresh token rejected" fallback against a mock auth server. To validate
//! it against real GitLab: revoke this app's authorization in GitLab
//! (User Settings → Applications → Authorized applications) while cached
//! credentials still exist, then re-run this test. The proxy must log the
//! failed refresh, clear the cache, and reopen the browser for a full
//! re-authorization — it must NOT exit with an error.

#![deny(clippy::unwrap_used)]

use std::time::Duration;

use rmcp::ServiceExt;
use rmcp::transport::child_process::TokioChildProcess;

/// The remote MCP server this test exercises. Hard-coded because the whole
/// point of the test is to validate OAuth against this specific endpoint.
const GITLAB_MCP_URL: &str = "https://gitlab.com/api/v4/mcp";

/// Custom header GitLab's MCP server honors to namespace its tool names.
/// With this prefix set, every tool name in `tools/list` should start with
/// `gitlab-` instead of the server's bare default. We use this both as a
/// realistic header-forwarding exercise *and* as an observable assertion
/// that the `--header` flag actually reaches the upstream.
const TOOL_PREFIX_HEADER: &str = "X-Gitlab-Mcp-Server-Tool-Name-Prefix: gitlab-";
const TOOL_PREFIX: &str = "gitlab-";

/// Upper bound on how long we'll wait for the user to complete the OAuth
/// flow. Matches the proxy's default `--auth-timeout-secs`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(300);

/// Upper bound on how long we'll wait for the `tools/list` round trip once
/// the proxy is authorized. Generous because the first call may also be
/// fetching a fresh access token from GitLab's auth server.
const TOOLS_LIST_TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test]
#[ignore = "hits gitlab.com; may open a browser for OAuth on first run"]
async fn e2e_gitlab_oauth_lists_tools() {
    // `CARGO_BIN_EXE_<bin-name>` is set by Cargo for integration tests; it
    // points at the freshly built binary so we always test the current
    // code, not whatever happens to be on $PATH.
    let bin = env!("CARGO_BIN_EXE_hyper-mcp-remote");
    eprintln!("e2e: spawning {bin} -> {GITLAB_MCP_URL}");

    // Build the spawn command. We deliberately do *not* pipe stderr: the
    // proxy prints the authorization URL to its own stderr, and we want
    // the human running `cargo test -- --ignored --nocapture` to see it
    // immediately so they can complete the OAuth flow.
    //
    // `--header` is the public-facing way to inject extra request headers
    // on every call to the remote; here we use GitLab's tool-name-prefix
    // header so the test can assert the header survived the trip through
    // the proxy by inspecting the resulting tool names.
    let mut cmd = tokio::process::Command::new(bin);
    cmd.arg(GITLAB_MCP_URL)
        .arg("--header")
        .arg(TOOL_PREFIX_HEADER);

    let proc = TokioChildProcess::new(cmd).expect("failed to spawn hyper-mcp-remote binary");
    let pid = proc.id();
    eprintln!("e2e: proxy pid={pid:?}");

    // `().serve(transport)` runs the MCP client handshake (initialize +
    // initialized) over the child's stdio. If the proxy needs to do OAuth
    // this future stays pending until the user finishes in the browser,
    // so we wrap it in a generous timeout rather than blocking forever.
    let client = tokio::time::timeout(HANDSHAKE_TIMEOUT, ().serve(proc))
        .await
        .expect("MCP handshake timed out (did you complete OAuth in the browser?)")
        .expect("MCP handshake failed");

    // The proxy advertises its own identity in `server_info`, not the
    // upstream's — this is the "capability reflection but with proxy
    // identity" behavior verified by the unit tests, here checked
    // against the real wire format.
    let info = client
        .peer_info()
        .expect("peer_info should be set after handshake");
    eprintln!(
        "e2e: connected; proxy reports server_info={} v{}",
        info.server_info.name, info.server_info.version
    );
    assert_eq!(
        info.server_info.name, "hyper-mcp-remote",
        "proxy must rewrite server_info.name to its own identity"
    );
    assert_eq!(
        info.server_info.version,
        env!("CARGO_PKG_VERSION"),
        "proxy server_info.version should match the crate version"
    );

    // GitLab's MCP server exposes a tools interface — verify the
    // capability reflection plumbed it through.
    assert!(
        info.capabilities.tools.is_some(),
        "GitLab MCP advertises tools; proxy must surface that capability"
    );

    // Now the real test: list tools end-to-end through the proxy. This
    // exercises the local stdio ServerHandler → Peer<RoleClient> →
    // StreamableHttpClientTransport → OAuth-refreshed reqwest::Client →
    // GitLab path.
    let tools = tokio::time::timeout(TOOLS_LIST_TIMEOUT, client.peer().list_tools(None))
        .await
        .expect("list_tools timed out")
        .expect("list_tools returned a protocol error");

    assert!(
        !tools.tools.is_empty(),
        "GitLab MCP server should expose at least one tool; got an empty list"
    );

    eprintln!("e2e: received {} tools from GitLab:", tools.tools.len());
    for tool in &tools.tools {
        eprintln!(
            "  - {} \u{2014} {}",
            tool.name,
            tool.description.as_deref().unwrap_or("(no description)")
        );
    }

    // Sanity-check that each tool has a valid object input schema. This
    // is a generic shape check that doesn't depend on which specific
    // tools GitLab decides to expose at any given moment.
    for tool in &tools.tools {
        assert_eq!(
            tool.input_schema.get("type").and_then(|v| v.as_str()),
            Some("object"),
            "tool '{}' must have inputSchema.type == \"object\"",
            tool.name
        );
    }

    // The `X-Gitlab-Mcp-Server-Tool-Name-Prefix: gitlab-` header we passed
    // via `--header` should have reached GitLab and caused every tool
    // name to be prefixed with `gitlab-`. If even one tool comes back
    // without the prefix, either the header didn't get forwarded or
    // GitLab silently ignored it — in either case the test must fail.
    let bad: Vec<&str> = tools
        .tools
        .iter()
        .map(|t| t.name.as_ref())
        .filter(|name| !name.starts_with(TOOL_PREFIX))
        .collect();
    assert!(
        bad.is_empty(),
        "every tool name should start with {TOOL_PREFIX:?} when the \
         X-Gitlab-Mcp-Server-Tool-Name-Prefix header is set; offenders: {bad:?}"
    );

    // Clean shutdown: cancel the client service. The proxy's own
    // SIGTERM/Ctrl-C handler isn't in play here because rmcp signals
    // shutdown by closing the stdio transport, which the proxy's
    // `tokio::select!` interprets as EOF and exits cleanly. Dropping the
    // `TokioChildProcess` would also work, but explicit cancel makes the
    // teardown deterministic.
    if let Err(e) = client.cancel().await {
        eprintln!("e2e: client.cancel() returned {e}; ignoring");
    }
}
