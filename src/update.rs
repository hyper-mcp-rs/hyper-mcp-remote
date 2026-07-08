//! Self-update support using the `self_update` and `self_update_extras` crates.
//!
//! This module provides a blocking `run_update()` function that checks GitHub
//! releases for newer versions of the binary, downloads and verifies them with
//! ed25519ph signatures, installs them via self-replacement, and (on POSIX
//! systems) re-executes the new binary.

use self_update::{backends::github::Update, cargo_crate_version};
use std::time::Duration;

/// Run the self-update flow.
///
/// This is a blocking function that:
/// 1. Configures the GitHub update backend
/// 2. Wraps it in throttle::Update to limit check frequency
/// 3. On non-Windows, wraps in restart::Update to re-execute after update
/// 4. Calls .update() to perform the actual update
///
/// On Windows, prints a warning and runs the update without restart (the
/// running binary continues until exit; the new binary takes effect on next launch).
///
/// All errors are logged internally and the function returns void.
pub fn update() {
    // Load the verifying key from the compiled-in public key file
    let key_bytes = include_bytes!("../keys/ed25519.pub");
    if key_bytes.len() != 32 {
        tracing::error!("ed25519.pub must contain exactly 32 bytes");
        return;
    }
    let verifying_key = [*key_bytes];

    // Build the GitHub backend
    let backend = match Update::configure()
        .repo_owner("hyper-mcp-rs")
        .repo_name("hyper-mcp-remote")
        .bin_name("hyper-mcp-remote")
        .current_version(cargo_crate_version!())
        .verifying_keys(verifying_key)
        .build()
    {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(%e, "failed to build GitHub update backend");
            return;
        }
    };

    // Wrap in throttle to limit check frequency
    let throttled = match self_update_extras::throttle::Update::configure()
        .release_update(backend)
        .throttle_window(Duration::from_secs(15 * 60)) // 15-minute window
        .build()
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(%e, "failed to build throttle wrapper");
            return;
        }
    };

    #[cfg(not(target_os = "windows"))]
    {
        // On POSIX systems, wrap in restart::Update to re-execute after update
        match self_update_extras::restart::Update::configure()
            .release_update(throttled)
            .guard_env("HYPER_MCP_REMOTE_AUTO_UPDATED")
            .build()
        {
            Ok(updater) => match updater.update() {
                Ok(status) => tracing::info!(?status, "update completed successfully"),
                Err(e) => tracing::error!(%e, "update failed"),
            },
            Err(e) => {
                tracing::error!(%e, "failed to build restart wrapper");
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // On Windows, we cannot replace a running .exe
        tracing::warn!(
            "self-update on Windows is not supported. Please update manually or rebuild."
        );
        match throttled.update() {
            Ok(status) => tracing::info!(?status, "update completed (no restart on Windows)"),
            Err(e) => tracing::error!(%e, "update failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_key_file_exists() {
        // Verify the key file exists and is the correct size
        let key_bytes = include_bytes!("../keys/ed25519.pub");
        assert_eq!(
            key_bytes.len(),
            32,
            "ed25519.pub must contain exactly 32 bytes for ed25519ph"
        );
    }

    #[test]
    fn test_update_flag_parsed() {
        // This test is covered by cli.rs tests
        // We keep this as a placeholder to document the expected behavior
    }

    #[test]
    fn test_update_flag_false_by_default() {
        // This test is covered by cli.rs tests
        // We keep this as a placeholder to document the expected behavior
    }
}
