//! `hyper-mcp-remote` — a stdio → Streamable-HTTP MCP proxy with OAuth.
//!
//! Spawned by an MCP client (Claude Desktop, Cursor, Zed, …) as a stdio
//! server, this binary forwards every MCP message to a remote Streamable-HTTP
//! MCP server. On first run, it performs the MCP-specified OAuth 2.1 flow
//! against the upstream and caches the resulting tokens in the OS-native
//! secret store so subsequent launches start without user interaction.

#![deny(clippy::unwrap_used)]

mod auth;
mod cli;
mod filter;
mod headers;
mod logging;
mod proxy;
mod session;
mod transport;

use anyhow::{Context, Result};
use clap::Parser;
use rmcp::service::{RoleServer, serve_directly_with_ct};
use rmcp::transport::io::stdio;
use tokio::signal;
use tokio_util::sync::CancellationToken;

use crate::cli::Cli;
use crate::filter::ToolFilter;
use crate::proxy::{KeepaliveConfig, ProxyHandler};
use crate::session::{CredentialKey, SessionHash};

#[tokio::main]
async fn main() -> Result<()> {
    // Tracing is installed via `logging.rs`'s `#[ctor]` before `main` runs;
    // it writes to a daily-rolling file rather than stderr so that nothing
    // ever interferes with the stdio MCP transport. The `logging` module is
    // referenced explicitly here only to ensure it is linked in.
    let _ = &logging::install_panic_hook;

    let cli = Cli::parse();
    cli.validate().context("invalid CLI arguments")?;

    let headers = headers::parse(&cli.headers).context("failed to parse --header arguments")?;
    let session = SessionHash::new(&cli.server_url, cli.resource.as_deref(), &headers);
    let cred_key = CredentialKey::new(&cli.server_url, cli.resource.as_deref());

    tracing::info!(
        server_url = %cli.server_url,
        %session,
        %cred_key,
        header_count = headers.len(),
        "starting hyper-mcp-remote"
    );

    // Run the auth dance (cached or interactive) and produce the HTTP client
    // that the streamable-http transport will drive.
    let auth_outcome = auth::acquire_auth_client(&cli, &cred_key, &headers)
        .await
        .context("failed to authenticate with remote MCP server")?;

    let transport = transport::build(&cli.server_url, headers, auth_outcome)
        .context("failed to build remote transport")?;

    let keepalive = KeepaliveConfig::from_secs(cli.ping_interval_secs, cli.ping_timeout_secs);
    let tool_filter = ToolFilter::from_cli(&cli.allow_tools, &cli.deny_tools)
        .context("failed to compile tool filter patterns")?;
    tracing::info!(
        ping_interval_secs = cli.ping_interval_secs,
        ping_timeout_secs = cli.ping_timeout_secs,
        allow_tool_patterns = cli.allow_tools.len(),
        deny_tool_patterns = cli.deny_tools.len(),
        tool_filter_active = !tool_filter.is_noop(),
        "Starting hyper-mcp-remote"
    );
    let handler = ProxyHandler::new(transport, keepalive, tool_filter);
    let ct = CancellationToken::new();
    let running =
        serve_directly_with_ct::<RoleServer, _, _, _, _>(handler, stdio(), None, ct.clone());

    tokio::select! {
        res = running.waiting() => {
            tracing::warn!(reason = ?res?, "Shutting down");
        }
        _ = signal::ctrl_c() => {
            tracing::warn!(reason = "SIGTERM", "Shutting down");
            ct.cancel();
        }
    }

    Ok(())
}
