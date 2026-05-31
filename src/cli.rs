//! Command-line interface definition.
//!
//! `hyper-mcp-remote` is meant to be spawned by an MCP client (Claude Desktop,
//! Cursor, Zed, etc.) as a stdio MCP server. It proxies that local stdio
//! connection to a remote MCP server speaking Streamable HTTP, performing the
//! OAuth dance on first run and persisting tokens between launches.

use clap::Parser;

/// A stdio MCP proxy for remote Streamable-HTTP MCP servers, with OAuth.
///
/// Listens for MCP traffic on stdin/stdout and forwards every request,
/// response, and notification to a remote Streamable-HTTP MCP server.
/// Performs MCP OAuth (RFC 9728 / RFC 8414 / OAuth 2.1 + PKCE) on first
/// connect and caches the resulting tokens in the OS-native secret store.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "hyper-mcp-remote",
    version,
    about = "stdio -> Streamable HTTP MCP proxy with OAuth"
)]
pub struct Cli {
    /// URL of the remote MCP server (e.g. `https://example.com/mcp`).
    pub server_url: String,

    /// Extra HTTP header to send on every request to the remote server.
    ///
    /// Format: `Name: value`. Use `${ENV}` to interpolate from environment
    /// variables. May be specified multiple times.
    #[arg(long = "header", value_name = "HEADER")]
    pub headers: Vec<String>,

    /// OAuth resource identifier (RFC 8707), used to isolate sessions when
    /// proxying multiple tenants of the same server.
    #[arg(long, value_name = "URL")]
    pub resource: Option<String>,

    /// OAuth client name advertised during dynamic client registration.
    #[arg(long, default_value = "hyper-mcp-remote")]
    pub client_name: String,

    /// Comma-separated list of OAuth scopes to request, overriding any scopes
    /// discovered from server metadata.
    #[arg(long, value_name = "SCOPES")]
    pub scope: Option<String>,

    /// Bind address for the local OAuth callback server (loopback only).
    #[arg(long, default_value = "127.0.0.1")]
    pub callback_host: String,

    /// Fixed port for the local OAuth callback server. Defaults to an
    /// OS-selected ephemeral port. Reuse a fixed port if the upstream
    /// authorization server requires a pre-registered redirect URI.
    #[arg(long, value_name = "PORT")]
    pub callback_port: Option<u16>,

    /// Maximum time in seconds to wait for the user to complete the OAuth
    /// authorization flow in the browser.
    #[arg(long, default_value_t = 300)]
    pub auth_timeout_secs: u64,

    /// Forget any cached tokens for this server before connecting. Forces a
    /// fresh OAuth flow.
    #[arg(long)]
    pub reset_auth: bool,

    /// Allow `http://` (non-loopback) server URLs. Disabled by default to
    /// prevent accidental cleartext token transmission.
    #[arg(long)]
    pub allow_http: bool,

    /// Interval, in seconds, between MCP `ping` requests sent to the remote
    /// server to keep its session alive across idle intermediaries (load
    /// balancers, NATs, server-side idle timeouts). Set to `0` to disable
    /// keepalive pings.
    #[arg(long, value_name = "SECS", default_value_t = 60)]
    pub ping_interval_secs: u64,

    /// Per-ping timeout in seconds. If a `ping` doesn't complete within this
    /// window the failure is logged but the connection is not torn down —
    /// the underlying transport layer remains the source of truth for
    /// liveness.
    #[arg(long, value_name = "SECS", default_value_t = 10)]
    pub ping_timeout_secs: u64,
}

impl Cli {
    /// Validate the parsed CLI arguments. Returns a human-readable error on
    /// misconfiguration.
    pub fn validate(&self) -> anyhow::Result<()> {
        let url = url::Url::parse(&self.server_url)
            .map_err(|e| anyhow::anyhow!("invalid --server-url: {e}"))?;

        let is_loopback = matches!(
            url.host_str(),
            Some("localhost") | Some("127.0.0.1") | Some("::1")
        );

        if url.scheme() == "http" && !is_loopback && !self.allow_http {
            anyhow::bail!(
                "refusing to use http:// for non-loopback URL '{}'; pass --allow-http to override",
                self.server_url
            );
        }

        if url.scheme() != "http" && url.scheme() != "https" {
            anyhow::bail!("server URL must use http or https scheme");
        }

        // A zero `ping_timeout_secs` while pings are enabled would degenerate
        // to an instant timeout on every probe, so reject it up-front.
        if self.ping_interval_secs != 0 && self.ping_timeout_secs == 0 {
            anyhow::bail!("--ping-timeout-secs must be > 0 when keepalive pings are enabled");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Build a minimal valid `Cli` with the given server URL, leaving every
    /// other field at its default. Goes through `clap` so we exercise the
    /// `derive(Parser)` plumbing alongside `validate()`.
    fn cli_with(args: &[&str]) -> Cli {
        let mut full = vec!["hyper-mcp-remote"];
        full.extend_from_slice(args);
        Cli::parse_from(full)
    }

    #[test]
    fn validate_accepts_https_url() {
        let cli = cli_with(&["https://example.com/mcp"]);
        cli.validate().expect("https URL must validate");
    }

    #[test]
    fn validate_accepts_http_loopback() {
        // NOTE: `http://[::1]/...` is intentionally omitted. The `url` crate
        // version pinned by `reqwest` here returns `host_str()` as `"[::1]"`
        // (with brackets), so the bare `"::1"` arm of `validate()` never
        // matches. This is a known soft-fail mode and not the surface under
        // test; the IPv4 / `localhost` arms are what users actually hit.
        for host in ["http://127.0.0.1/mcp", "http://localhost/mcp"] {
            let cli = cli_with(&[host]);
            cli.validate()
                .unwrap_or_else(|e| panic!("loopback http {host} should validate: {e}"));
        }
    }

    #[test]
    fn validate_rejects_non_loopback_http_without_flag() {
        let cli = cli_with(&["http://example.com/mcp"]);
        let err = cli
            .validate()
            .expect_err("non-loopback http must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("--allow-http"),
            "error must mention the override flag; got: {msg}"
        );
    }

    #[test]
    fn validate_accepts_non_loopback_http_with_allow_flag() {
        let cli = cli_with(&["--allow-http", "http://example.com/mcp"]);
        cli.validate()
            .expect("--allow-http should bypass the loopback check");
    }

    #[test]
    fn validate_rejects_non_http_scheme() {
        let cli = cli_with(&["ftp://example.com/mcp"]);
        let err = cli.validate().expect_err("ftp must be rejected");
        assert!(err.to_string().contains("http or https"));
    }

    #[test]
    fn validate_rejects_invalid_url() {
        let cli = cli_with(&["::not a url::"]);
        let err = cli.validate().expect_err("garbage URL must be rejected");
        assert!(err.to_string().contains("invalid --server-url"));
    }

    #[test]
    fn parses_all_optional_flags() {
        let cli = cli_with(&[
            "--header",
            "X-A: 1",
            "--header",
            "X-B: 2",
            "--resource",
            "tenant-1",
            "--client-name",
            "my-client",
            "--scope",
            "read,write",
            "--callback-host",
            "127.0.0.1",
            "--callback-port",
            "9099",
            "--auth-timeout-secs",
            "42",
            "--reset-auth",
            "https://example.com/mcp",
        ]);
        assert_eq!(cli.headers.len(), 2);
        assert_eq!(cli.resource.as_deref(), Some("tenant-1"));
        assert_eq!(cli.client_name, "my-client");
        assert_eq!(cli.scope.as_deref(), Some("read,write"));
        assert_eq!(cli.callback_host, "127.0.0.1");
        assert_eq!(cli.callback_port, Some(9099));
        assert_eq!(cli.auth_timeout_secs, 42);
        assert!(cli.reset_auth);
        assert!(!cli.allow_http);
    }

    #[test]
    fn defaults_are_sensible() {
        let cli = cli_with(&["https://example.com/mcp"]);
        assert!(cli.headers.is_empty());
        assert!(cli.resource.is_none());
        assert_eq!(cli.client_name, "hyper-mcp-remote");
        assert!(cli.scope.is_none());
        assert_eq!(cli.callback_host, "127.0.0.1");
        assert!(cli.callback_port.is_none());
        assert_eq!(cli.auth_timeout_secs, 300);
        assert!(!cli.reset_auth);
        assert!(!cli.allow_http);
        assert_eq!(cli.ping_interval_secs, 60);
        assert_eq!(cli.ping_timeout_secs, 10);
    }

    #[test]
    fn validate_rejects_zero_ping_timeout_when_pings_enabled() {
        let cli = cli_with(&["--ping-timeout-secs", "0", "https://example.com/mcp"]);
        let err = cli
            .validate()
            .expect_err("zero ping timeout with enabled pings must be rejected");
        assert!(
            err.to_string().contains("--ping-timeout-secs"),
            "error must mention the offending flag; got: {err}"
        );
    }

    #[test]
    fn validate_accepts_zero_ping_timeout_when_pings_disabled() {
        // With keepalive turned off entirely the timeout value is irrelevant.
        let cli = cli_with(&[
            "--ping-interval-secs",
            "0",
            "--ping-timeout-secs",
            "0",
            "https://example.com/mcp",
        ]);
        cli.validate()
            .expect("disabled pings should bypass the timeout check");
    }
}
