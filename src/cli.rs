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
    ///
    /// Required to run the proxy. It may be omitted only when `--update` is
    /// passed on its own, in which case the binary performs the self-update
    /// check and exits. An empty value is rejected by `validate()`.
    #[arg(default_value = "")]
    pub server_url: String,

    /// Extra HTTP header to send on every request to the remote server.
    ///
    /// Format: `Name: value`. Use `${ENV}` to interpolate from environment
    /// variables. May be specified multiple times.
    #[arg(long = "header", value_name = "HEADER")]
    pub headers: Vec<String>,

    /// OAuth resource identifier (RFC 8707): the MCP server's canonical URL,
    /// sent to the authorization server as the token audience and used as the
    /// base URL for OAuth discovery in place of <SERVER_URL>.
    ///
    /// Must be an absolute http(s) URL without a fragment, matching the
    /// `resource` field the server advertises in its Protected Resource
    /// Metadata (RFC 9728). Distinct values also isolate cached credentials,
    /// e.g. when proxying multiple tenants of the same server via
    /// tenant-specific resource URLs.
    #[arg(long, value_name = "URL")]
    pub resource: Option<url::Url>,

    /// OAuth client name advertised during dynamic client registration.
    #[arg(long, default_value = "hyper-mcp-remote")]
    pub client_name: String,

    /// Pre-registered OAuth client ID; skips RFC 7591 dynamic client
    /// registration. Required for identity providers that do not support
    /// DCR (e.g. Microsoft Entra ID).
    ///
    /// The value is either the client ID itself, or an `https://` URL to a
    /// Client ID Metadata Document — the document is fetched and its
    /// `client_id` field is used.
    ///
    /// Most IdPs that require pre-registration also require a pre-registered
    /// redirect URI; pair this with `--callback-port` so the loopback
    /// redirect is stable across runs.
    #[arg(long, value_name = "ID_OR_URL")]
    pub client_id: Option<String>,

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

    /// Skip OAuth discovery and authentication entirely; talk to the remote
    /// server anonymously (or with whatever `--header` values you supply).
    ///
    /// Use this for MCP servers that either accept unauthenticated traffic
    /// but signal their session state with a non-spec-compliant `401` (e.g.
    /// stateful Streamable-HTTP servers gated on `Mcp-Session-Id`), or that
    /// use a static credential passed via `--header Authorization: ...`.
    /// When set, no probe, no PRM lookup, and no OAuth flow are performed.
    #[arg(long)]
    pub no_auth: bool,

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

    /// Restrict the proxy to only forward tools whose name matches one of
    /// these glob patterns. May be specified multiple times; values may
    /// also be comma-separated. When omitted, every tool the remote
    /// advertises is forwarded (subject to `--deny-tool`).
    ///
    /// Patterns are globs (`*`, `?`, `[abc]`) matched against the full
    /// tool name. Example: `--allow-tool 'read_*,search_*'`.
    #[arg(long = "allow-tool", value_name = "PATTERN")]
    pub allow_tools: Vec<String>,

    /// Drop any tool whose name matches one of these glob patterns. Applied
    /// after `--allow-tool`, so `--allow-tool 'read_*' --deny-tool
    /// 'read_secrets'` allows the family minus that one. Repeatable; values
    /// may also be comma-separated.
    #[arg(long = "deny-tool", value_name = "PATTERN")]
    pub deny_tools: Vec<String>,

    /// Check for a newer release and self-update.
    ///
    /// Checks the latest GitHub release for a newer version of
    /// `hyper-mcp-remote` and, if one is found, downloads it, verifies its
    /// ed25519ph signature, and replaces the running binary. On POSIX the
    /// process then re-executes into the new binary; on Windows it logs a
    /// warning and the new binary takes effect on the next launch.
    ///
    /// Run on its own (without <SERVER_URL>) to update and exit. If a
    /// <SERVER_URL> is also given, the update check runs first and then the
    /// proxy starts as usual.
    ///
    /// By default the update runs silently and without prompting, so it is
    /// safe when the process is a stdio MCP server (stdout carries the
    /// protocol stream). Pass `--verbose` for an interactive, visible update
    /// when running from a terminal.
    #[arg(long)]
    pub update: bool,

    /// Make the self-update interactive and verbose.
    ///
    /// This flag only affects `--update`; it has no bearing on the proxy
    /// server. When set, the updater prints its progress to stdout and
    /// prompts for confirmation before replacing the binary, instead of
    /// running silently. Use this only from a real terminal: the visible
    /// output would corrupt a stdio MCP session.
    #[arg(long)]
    pub verbose: bool,
}

impl Cli {
    /// Validate the parsed CLI arguments. Returns a human-readable error on
    /// misconfiguration.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.server_url.is_empty() {
            anyhow::bail!(
                "missing <SERVER_URL>: a remote MCP server URL is required (it may be \
                 omitted only when running --update on its own)"
            );
        }

        let url = url::Url::parse(&self.server_url)
            .map_err(|e| anyhow::anyhow!("invalid --server-url: {e}"))?;
        self.check_http_scheme(&url, "server URL")?;

        if let Some(resource) = &self.resource {
            // RFC 8707 §2: the resource indicator MUST NOT include a
            // fragment component.
            if resource.fragment().is_some() {
                anyhow::bail!("--resource must not include a fragment (RFC 8707): '{resource}'");
            }
            // rmcp fetches Protected Resource Metadata from this URL and
            // sends bearer-token requests derived from it, so it is subject
            // to the same scheme rules as the server URL itself. (RFC 8707
            // also permits abstract URIs such as URNs, but those can never
            // work as an OAuth discovery base URL.)
            self.check_http_scheme(resource, "--resource URL")?;
        }

        // A zero `ping_timeout_secs` while pings are enabled would degenerate
        // to an instant timeout on every probe, so reject it up-front.
        if self.ping_interval_secs != 0 && self.ping_timeout_secs == 0 {
            anyhow::bail!("--ping-timeout-secs must be > 0 when keepalive pings are enabled");
        }

        Ok(())
    }

    /// Shared transport policy for any URL the proxy sends credentials to:
    /// https always; http only for loopback hosts unless `--allow-http`.
    fn check_http_scheme(&self, url: &url::Url, what: &str) -> anyhow::Result<()> {
        let is_loopback = matches!(
            url.host_str(),
            Some("localhost") | Some("127.0.0.1") | Some("::1")
        );

        if url.scheme() == "http" && !is_loopback && !self.allow_http {
            anyhow::bail!(
                "refusing to use http:// for non-loopback {what} '{url}'; pass --allow-http to override"
            );
        }

        if url.scheme() != "http" && url.scheme() != "https" {
            anyhow::bail!("{what} must use http or https scheme");
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
            "https://example.com/mcp/tenant-1",
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
        assert_eq!(
            cli.resource.as_ref().map(url::Url::as_str),
            Some("https://example.com/mcp/tenant-1")
        );
        assert_eq!(cli.client_name, "my-client");
        assert_eq!(cli.scope.as_deref(), Some("read,write"));
        assert_eq!(cli.callback_host, "127.0.0.1");
        assert_eq!(cli.callback_port, Some(9099));
        assert_eq!(cli.auth_timeout_secs, 42);
        assert!(cli.reset_auth);
        assert!(!cli.allow_http);
    }

    #[test]
    fn resource_rejects_non_url_at_parse_time() {
        // Before `--resource` became rmcp's OAuth base_url this value was
        // accepted (and silently unused). Now it must parse as a URL, and
        // the failure must surface as a clear clap error at startup rather
        // than a cryptic OAuth state-machine failure at connect time.
        let res = Cli::try_parse_from([
            "hyper-mcp-remote",
            "--resource",
            "tenant-1",
            "https://example.com/mcp",
        ]);
        assert!(res.is_err(), "bare label must be rejected at parse time");
    }

    #[test]
    fn validate_rejects_resource_with_fragment() {
        let cli = cli_with(&[
            "--resource",
            "https://example.com/mcp#frag",
            "https://example.com/mcp",
        ]);
        let err = cli
            .validate()
            .expect_err("fragment in --resource must be rejected (RFC 8707)");
        assert!(err.to_string().contains("fragment"), "got: {err}");
    }

    #[test]
    fn validate_rejects_non_http_resource_scheme() {
        // RFC 8707 permits abstract URIs (e.g. URNs) — and `url::Url`
        // happily parses them — but rmcp fetches metadata from this URL,
        // so only http(s) can ever work here.
        let cli = cli_with(&["--resource", "urn:example:cal", "https://example.com/mcp"]);
        let err = cli.validate().expect_err("urn --resource must be rejected");
        assert!(err.to_string().contains("http or https"), "got: {err}");
    }

    #[test]
    fn validate_rejects_non_loopback_http_resource_without_flag() {
        let cli = cli_with(&[
            "--resource",
            "http://example.com/mcp",
            "https://example.com/mcp",
        ]);
        let err = cli
            .validate()
            .expect_err("non-loopback http --resource must be rejected");
        assert!(err.to_string().contains("--allow-http"), "got: {err}");
    }

    #[test]
    fn validate_accepts_http_resource_with_allow_flag() {
        let cli = cli_with(&[
            "--allow-http",
            "--resource",
            "http://example.com/mcp",
            "https://example.com/mcp",
        ]);
        cli.validate()
            .expect("--allow-http must apply to --resource too");
    }

    #[test]
    fn defaults_are_sensible() {
        let cli = cli_with(&["https://example.com/mcp"]);
        assert!(cli.headers.is_empty());
        assert!(cli.resource.is_none());
        assert_eq!(cli.client_name, "hyper-mcp-remote");
        assert!(cli.client_id.is_none());
        assert!(cli.scope.is_none());
        assert_eq!(cli.callback_host, "127.0.0.1");
        assert!(cli.callback_port.is_none());
        assert_eq!(cli.auth_timeout_secs, 300);
        assert!(!cli.reset_auth);
        assert!(!cli.allow_http);
        assert!(!cli.no_auth);
        assert_eq!(cli.ping_interval_secs, 60);
        assert_eq!(cli.ping_timeout_secs, 10);
        assert!(cli.allow_tools.is_empty());
        assert!(cli.deny_tools.is_empty());
    }

    #[test]
    fn parses_repeated_tool_filter_flags() {
        let cli = cli_with(&[
            "--allow-tool",
            "read_*",
            "--allow-tool",
            "search",
            "--deny-tool",
            "read_secrets",
            "https://example.com/mcp",
        ]);
        assert_eq!(cli.allow_tools, vec!["read_*", "search"]);
        assert_eq!(cli.deny_tools, vec!["read_secrets"]);
        // Filter values are opaque to `validate()`; they're compiled later
        // by `ToolFilter::from_cli`, so validation must still pass.
        cli.validate().expect("tool filter flags must validate");
    }

    #[test]
    fn parses_comma_separated_tool_filter_value() {
        // Clap stores the raw value verbatim; comma-splitting happens in
        // `ToolFilter::from_cli`. We just confirm clap doesn't reject the
        // string and that it's preserved.
        let cli = cli_with(&["--allow-tool", "a,b,c", "https://example.com/mcp"]);
        assert_eq!(cli.allow_tools, vec!["a,b,c"]);
    }

    #[test]
    fn parses_client_id_as_plain_string() {
        let cli = cli_with(&[
            "--client-id",
            "11111111-2222-3333-4444-555555555555",
            "https://example.com/mcp",
        ]);
        assert_eq!(
            cli.client_id.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
        cli.validate().expect("--client-id must validate");
    }

    #[test]
    fn parses_client_id_as_metadata_url() {
        let cli = cli_with(&[
            "--client-id",
            "https://example.com/client-metadata.json",
            "https://example.com/mcp",
        ]);
        assert_eq!(
            cli.client_id.as_deref(),
            Some("https://example.com/client-metadata.json"),
            "URL values are stored verbatim; resolution happens in the auth module"
        );
    }

    #[test]
    fn parses_no_auth_flag() {
        let cli = cli_with(&["--no-auth", "https://example.com/mcp"]);
        assert!(cli.no_auth, "--no-auth must set the flag");
        cli.validate()
            .expect("--no-auth must compose with normal validation");
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

    #[test]
    fn parses_update_flag() {
        let cli = cli_with(&["--update", "https://example.com/mcp"]);
        assert!(cli.update, "--update must set the flag");
    }

    #[test]
    fn update_flag_is_false_by_default() {
        let cli = cli_with(&["https://example.com/mcp"]);
        assert!(!cli.update, "--update must default to false");
    }

    #[test]
    fn parses_verbose_flag() {
        let cli = cli_with(&["--update", "--verbose", "https://example.com/mcp"]);
        assert!(cli.verbose, "--verbose must set the flag");
    }

    #[test]
    fn verbose_flag_is_false_by_default() {
        let cli = cli_with(&["--update", "https://example.com/mcp"]);
        assert!(!cli.verbose, "--verbose must default to false");
    }

    #[test]
    fn update_parses_without_server_url() {
        // `--update` (optionally with `--verbose`) must parse stand-alone,
        // leaving `server_url` empty so main can update and exit.
        let cli = cli_with(&["--update", "--verbose"]);
        assert!(cli.update);
        assert!(cli.verbose);
        assert!(
            cli.server_url.is_empty(),
            "server_url must default to empty when omitted"
        );
    }

    #[test]
    fn validate_rejects_empty_server_url() {
        let cli = cli_with(&["--update"]);
        let err = cli
            .validate()
            .expect_err("an empty server URL must be rejected");
        assert!(
            err.to_string().contains("SERVER_URL"),
            "error should name the missing SERVER_URL, got: {err}"
        );
    }
}
