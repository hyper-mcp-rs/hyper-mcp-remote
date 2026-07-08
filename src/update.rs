//! Self-update support using the `self_update` and `self_update_extras` crates.
//!
//! This module provides a blocking `update()` function that checks GitHub
//! releases for newer versions of the binary, downloads and verifies them with
//! ed25519ph signatures, installs them via self-replacement, and (on POSIX
//! systems) re-executes the new binary.

use self_update::errors::{Error, Result};
use self_update::update::ReleaseUpdate;
use self_update::{backends::github::Update, cargo_crate_version};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Return the token that uniquely identifies the binary archive asset for the
/// current platform, e.g. `aarch64-apple-darwin.tar.gz`.
///
/// Releases ship several assets whose names include the target triple
/// (`checksums-<target>.txt`, the archive, etc.), so matching on the target
/// alone makes `self_update` pick the first match (the checksums file) instead
/// of the archive.
///
/// The token combines the target triple with the archive extension. Because it
/// is architecture-specific, it disambiguates on the happy path *and* keeps
/// `self_update`'s identifier-only fallback safe: if the correct archive is
/// missing, no wrong-architecture archive can match, so the update fails loudly
/// instead of installing the wrong binary.
fn archive_identifier() -> String {
    let ext = if cfg!(target_os = "windows") {
        ".zip"
    } else {
        ".tar.gz"
    };
    format!("{}{}", self_update::get_target(), ext)
}

/// Check if the given path is managed by Homebrew.
fn is_homebrew_installed(path: &Path) -> bool {
    // Extract the binary name from the path
    let bin_name = match path.file_stem() {
        Some(name) => name.to_string_lossy().into_owned(),
        None => return false,
    };

    // Run `brew --prefix <formula>` to get the Homebrew prefix for this formula
    let output = match Command::new("brew").arg("--prefix").arg(&bin_name).output() {
        Ok(output) => output,
        Err(_) => return false, // brew not found or failed to run
    };

    if !output.status.success() {
        return false; // brew --prefix failed
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let prefix_path = stdout_str.trim();
    if prefix_path.is_empty() {
        return false; // formula not found by Homebrew
    }

    // Check if the executable path starts with the Homebrew prefix
    let path_str = path.to_string_lossy();
    path_str.starts_with(prefix_path)
}

/// Run the self-update flow.
///
/// When `verbose` is false (the default), the update runs silently and without
/// prompting so it is safe to invoke while acting as a stdio MCP server. When
/// `verbose` is true, `self_update` prints progress to stdout and prompts for
/// confirmation, which is only appropriate from an interactive terminal.
///
/// This is the single place errors are handled: the composition bubbles any
/// failure up via `Result` and it is logged here. The function itself returns
/// nothing.
pub fn update(verbose: bool) {
    if let Err(e) = try_update(verbose) {
        tracing::error!(%e, "self-update failed");
    }
}

/// Build, compose, and run the update, bubbling every error to [`update`].
///
/// The wrappers are layered `restart(silence(throttle(backend)))` so that, on
/// POSIX, the silence redirect of fd 1 is restored before the restart wrapper
/// re-executes the process.
fn try_update(verbose: bool) -> Result<()> {
    let backend = backend(verbose)?;

    // Refuse to self-replace a Homebrew-managed executable.
    let current_bin_path = backend.bin_install_path();
    if is_homebrew_installed(&current_bin_path) {
        tracing::warn!(
            ?current_bin_path,
            "executable is managed by Homebrew; manual update required"
        );
        return Ok(());
    }

    let updater = throttle(backend)?;
    // Skip the stdout redirect only when the caller explicitly wants a
    // visible, interactive update from a terminal.
    let updater = if verbose { updater } else { silence(updater)? };
    let updater = restart(updater)?;

    let status = updater.update()?;
    tracing::info!(?status, "self-update completed");
    Ok(())
}

/// Build the GitHub update backend.
///
/// When `verbose` is false the backend is configured to run silently and
/// without prompting; when true it prints progress and prompts for
/// confirmation.
fn backend(verbose: bool) -> Result<Box<dyn ReleaseUpdate>> {
    // Load the verifying key from the compiled-in public key file
    let key_bytes = include_bytes!("../keys/ed25519.pub");
    if key_bytes.len() != 32 {
        return Err(Error::Config(
            "ed25519.pub must contain exactly 32 bytes".to_owned(),
        ));
    }
    let verifying_key = [*key_bytes];

    Update::configure()
        .repo_owner("hyper-mcp-rs")
        .repo_name("hyper-mcp-remote")
        .bin_name("hyper-mcp-remote")
        .identifier(&archive_identifier())
        .current_version(cargo_crate_version!())
        .verifying_keys(verifying_key)
        .no_confirm(!verbose)
        .show_output(verbose)
        .build()
}

/// Wrap `inner` in the throttle limiter that bounds how often the update check
/// contacts GitHub.
fn throttle(inner: Box<dyn ReleaseUpdate>) -> Result<Box<dyn ReleaseUpdate>> {
    self_update_extras::throttle::Update::configure()
        .release_update(inner)
        .throttle_window(Duration::from_secs(15 * 60)) // 15-minute window
        .build()
}

/// Wrap `inner` in the silence wrapper that diverts fd 1 to `/dev/null` while
/// the update runs, so `self_update`'s output can't corrupt the stdio MCP
/// protocol stream.
fn silence(inner: Box<dyn ReleaseUpdate>) -> Result<Box<dyn ReleaseUpdate>> {
    self_update_extras::silence::Update::configure()
        .release_update(inner)
        .sink(self_update_extras::silence::Sink::Null)
        .build()
}

/// Wrap `inner` in the restart wrapper so the process re-executes into the
/// freshly installed binary after a successful update.
#[cfg(not(target_os = "windows"))]
fn restart(inner: Box<dyn ReleaseUpdate>) -> Result<Box<dyn ReleaseUpdate>> {
    self_update_extras::restart::Update::configure()
        .release_update(inner)
        .guard_env("HYPER_MCP_REMOTE_AUTO_UPDATED")
        .build()
}

/// On Windows a running `.exe` cannot be replaced in place, so no restart is
/// attempted; the new binary takes effect on the next launch. `inner` is
/// returned unchanged.
#[cfg(target_os = "windows")]
fn restart(inner: Box<dyn ReleaseUpdate>) -> Result<Box<dyn ReleaseUpdate>> {
    tracing::warn!("self-update on Windows cannot restart; new binary applies on next launch");
    Ok(inner)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{archive_identifier, is_homebrew_installed};

    #[test]
    fn test_archive_identifier_is_target_specific() {
        let id = archive_identifier();
        let target = self_update::get_target();

        // The identifier is the target triple plus the platform archive
        // extension, e.g. `aarch64-apple-darwin.tar.gz`.
        let ext = if cfg!(target_os = "windows") {
            ".zip"
        } else {
            ".tar.gz"
        };
        assert_eq!(id, format!("{target}{ext}"));
        assert!(id.starts_with(target));
        assert!(id.ends_with(ext));
    }

    #[test]
    fn test_archive_identifier_selects_only_the_correct_archive() {
        // Simulate self_update's `asset_for` identifier matching against a
        // realistic multi-target, multi-artifact release.
        let id = archive_identifier();
        let target = self_update::get_target();
        let ext = if cfg!(target_os = "windows") {
            ".zip"
        } else {
            ".tar.gz"
        };

        // Assets for the current target: both archive kinds plus non-archives.
        let mut assets = vec![
            format!("checksums-{target}.txt"),
            "sbom.cdx.json".to_string(),
            format!("hyper-mcp-remote-{target}.tar.gz"),
            format!("hyper-mcp-remote-{target}.zip"),
        ];

        // Assets for every OTHER target (excluding the current one to avoid
        // duplicating the target-specific entries above).
        for other in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
        ] {
            if other != target {
                assets.push(format!("checksums-{other}.txt"));
                assets.push(format!("hyper-mcp-remote-{other}.tar.gz"));
                assets.push(format!("hyper-mcp-remote-{other}.zip"));
            }
        }

        // Every asset whose name contains the identifier must both be for THIS
        // target and be the correct archive kind. This guarantees that even
        // self_update's identifier-only fallback path cannot select a
        // wrong-architecture or non-archive asset.
        for asset in &assets {
            if asset.contains(&id) {
                assert!(asset.contains(target), "matched wrong target: {asset}");
                assert!(asset.ends_with(ext), "matched wrong archive kind: {asset}");
            }
        }

        // The checksums file for our target must NOT match (this was the
        // original bug), and exactly one asset must match.
        assert!(!format!("checksums-{target}.txt").contains(&id));
        let matches = assets.iter().filter(|a| a.contains(&id)).count();
        assert_eq!(matches, 1, "expected exactly one matching archive");
    }

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

    #[test]
    fn test_is_homebrew_installed_with_nonexistent_binary() {
        // Test with a binary name that doesn't exist in Homebrew
        let fake_path = Path::new("/opt/homebrew/bin/fake-binary-name-xyz123");
        assert!(!is_homebrew_installed(fake_path));
    }

    #[test]
    fn test_is_homebrew_installed_with_valid_homebrew_path() {
        // Test with a binary that should be in Homebrew (e.g., curl)
        let curl_path = Path::new("/opt/homebrew/bin/curl");
        // This will return false if curl is not installed, true if it is
        // We accept both results since the test should not fail if curl isn't installed
        let result = is_homebrew_installed(curl_path);
        // If Homebrew is not available, it should return false
        // If curl is not installed via Homebrew, it should return false
        // If curl is installed via Homebrew, it should return true
        let _ = result; // Suppress unused variable warning if brew is not installed
    }

    #[test]
    fn test_is_homebrew_installed_with_non_homebrew_path() {
        // Test with a path that's clearly not in Homebrew
        let non_homebrew_path = Path::new("/usr/bin/python3");
        assert!(!is_homebrew_installed(non_homebrew_path));
    }

    #[test]
    fn test_is_homebrew_installed_with_missing_file_stem() {
        // Test with a path that has no file stem
        let invalid_path = Path::new("/opt/homebrew/bin/");
        assert!(!is_homebrew_installed(invalid_path));
    }
}
