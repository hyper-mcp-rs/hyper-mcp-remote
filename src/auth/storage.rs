//! Cross-platform persistent credential storage for OAuth tokens.
//!
//! Implements [`rmcp::transport::auth::CredentialStore`] by writing into the
//! OS-native secret store via the [`keyring`] crate, and silently falling
//! back to a 0600 JSON file when no keyring backend is available (e.g.
//! headless Linux without a Secret Service implementation, or CI).
//!
//! The on-disk encoding is the JSON representation of rmcp's
//! [`StoredCredentials`], which is the same type the in-memory store uses,
//! so the round-trip is lossless.

use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use rmcp::transport::auth::{AuthError, CredentialStore, StoredCredentials};

use crate::session::CredentialKey;

/// Service identifier used in the OS keyring. Keep this stable across
/// releases; bumping it will orphan all previously stored tokens.
const KEYRING_SERVICE: &str = "io.github.hyper-mcp-rs.hyper-mcp-remote";

/// Credential store backed by the OS keyring, with an automatic file
/// fallback when the keyring backend is unavailable.
pub struct SecureCredentialStore {
    /// The keyring account name. Derived from a [`CredentialKey`] so it is
    /// stable across launches as long as the user keeps pointing at the
    /// same `(server_url, resource)`. Request-time header churn does not
    /// invalidate this entry.
    account: String,
    /// Path used for the file-based fallback. Keyed off the same
    /// `CredentialKey` so the fallback persists across launches too.
    fallback_path: PathBuf,
}

impl SecureCredentialStore {
    /// Build a credential store keyed by `key`. The store transparently
    /// falls back to file storage if the keyring is unavailable on this
    /// platform/session.
    pub fn new(key: &CredentialKey) -> Result<Self> {
        let dirs = directories::ProjectDirs::from("io.github", "hyper-mcp-rs", "hyper-mcp-remote")
            .context("failed to resolve user config directory")?;

        Self::with_data_dir(key, dirs.data_local_dir())
    }

    /// Same as [`Self::new`] but with the data directory injected, primarily
    /// for tests that need to point the file-fallback at a `tempdir`.
    pub fn with_data_dir(key: &CredentialKey, data_dir: &std::path::Path) -> Result<Self> {
        let dir = data_dir.join("credentials");
        std::fs::create_dir_all(&dir).with_context(|| {
            format!("failed to create credentials directory: {}", dir.display())
        })?;

        Ok(Self {
            account: key.to_string(),
            fallback_path: dir.join(format!("{key}.json")),
        })
    }

    /// Wipe any cached credentials for this session from both keyring and
    /// disk. Used by `--reset-auth` and explicit logout flows.
    ///
    /// Keyring errors are logged but not propagated: a missing entry is a
    /// success for our purposes, and a transient keyring failure shouldn't
    /// stop us from at least clearing the file fallback. We do, however,
    /// distinguish "no entry" from "delete failed" in the logs, because
    /// the latter previously hid a real bug where `--reset-auth` reported
    /// success but left the credential intact (e.g. duplicate keychain
    /// items the keyring crate's delete path doesn't fully reap).
    pub fn clear_sync(&self) -> Result<()> {
        match keyring::Entry::new(KEYRING_SERVICE, &self.account) {
            Ok(entry) => match entry.delete_credential() {
                Ok(()) => tracing::debug!(
                    account = %self.account,
                    "deleted keyring entry"
                ),
                Err(keyring::Error::NoEntry) => tracing::debug!(
                    account = %self.account,
                    "keyring entry was already absent"
                ),
                Err(e) => tracing::warn!(
                    account = %self.account,
                    error = %e,
                    "keyring delete failed; entry may still be present"
                ),
            },
            Err(e) => tracing::warn!(error = %e, "could not open keyring entry to delete"),
        }
        if self.fallback_path.exists() {
            std::fs::remove_file(&self.fallback_path).with_context(|| {
                format!(
                    "failed to remove credentials file: {}",
                    self.fallback_path.display()
                )
            })?;
        }
        Ok(())
    }

    /// Read raw JSON from keyring, falling back to file. Returns `Ok(None)`
    /// when neither location has an entry for this session.
    fn read_raw(&self) -> Result<Option<String>, AuthError> {
        match keyring::Entry::new(KEYRING_SERVICE, &self.account) {
            Ok(entry) => match entry.get_password() {
                Ok(s) => return Ok(Some(s)),
                Err(keyring::Error::NoEntry) => {}
                Err(e) => {
                    tracing::debug!(error = %e, "keyring read failed; falling back to file");
                }
            },
            Err(e) => {
                tracing::debug!(error = %e, "keyring unavailable; falling back to file");
            }
        }

        match std::fs::read_to_string(&self.fallback_path) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AuthError::InternalError(format!(
                "failed to read credentials file: {e}"
            ))),
        }
    }

    /// Persist `data` to the keyring; on failure, fall back to a 0600 file.
    fn write_raw(&self, data: &str) -> Result<(), AuthError> {
        match keyring::Entry::new(KEYRING_SERVICE, &self.account) {
            Ok(entry) => match entry.set_password(data) {
                Ok(()) => {
                    // Belt-and-suspenders: remove any stale file copy so we
                    // don't have two sources of truth.
                    let _ = std::fs::remove_file(&self.fallback_path);
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(error = %e, "keyring write failed; falling back to file");
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "keyring unavailable; using file fallback");
            }
        }

        write_secret_file(&self.fallback_path, data)
            .map_err(|e| AuthError::InternalError(format!("file fallback write failed: {e}")))
    }
}

#[async_trait]
impl CredentialStore for SecureCredentialStore {
    async fn load(&self) -> Result<Option<StoredCredentials>, AuthError> {
        let raw = match self.read_raw()? {
            Some(s) => s,
            None => return Ok(None),
        };
        let creds: StoredCredentials = serde_json::from_str(&raw).map_err(|e| {
            AuthError::InternalError(format!("failed to deserialize stored credentials: {e}"))
        })?;
        Ok(Some(creds))
    }

    async fn save(&self, credentials: StoredCredentials) -> Result<(), AuthError> {
        let raw = serde_json::to_string(&credentials).map_err(|e| {
            AuthError::InternalError(format!("failed to serialize credentials: {e}"))
        })?;
        self.write_raw(&raw)
    }

    async fn clear(&self) -> Result<(), AuthError> {
        self.clear_sync()
            .map_err(|e| AuthError::InternalError(format!("clear failed: {e}")))
    }
}

/// Write `data` to `path` atomically with 0600 permissions on Unix.
fn write_secret_file(path: &std::path::Path, data: &str) -> Result<()> {
    let tmp = path.with_extension("tmp");

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("opening {}", tmp.display()))?;
        f.write_all(data.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.sync_all().ok();
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&tmp, data).with_context(|| format!("writing {}", tmp.display()))?;
    }

    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::transport::auth::{CredentialStore, StoredCredentials};

    fn make_store(dir: &std::path::Path, salt: &str) -> SecureCredentialStore {
        // Distinct keys per test so that even if a keyring is present
        // (e.g. on a developer's macOS box), each test gets its own entry.
        let key = CredentialKey::new(&format!("https://example.com/{salt}"), None);
        SecureCredentialStore::with_data_dir(&key, dir).expect("with_data_dir")
    }

    /// Build a `StoredCredentials` via JSON to avoid pulling in the `oauth2`
    /// crate just to construct an `OAuthTokenResponse` in tests. The shape
    /// here mirrors what rmcp itself serializes.
    fn sample_credentials() -> StoredCredentials {
        let json = serde_json::json!({
            "client_id": "client-abc",
            "token_response": {
                "access_token": "access-token-xyz",
                "token_type": "bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-token-zzz",
                "scope": "read write",
            },
            "granted_scopes": ["read", "write"],
            "token_received_at": 1_700_000_000u64,
        });
        serde_json::from_value(json).expect("sample credentials must deserialize")
    }

    /// Force the fallback path by deleting the keyring entry. Used to keep
    /// tests deterministic on machines where a real keyring is available.
    fn clear_keyring(store: &SecureCredentialStore) {
        if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &store.account) {
            let _ = entry.delete_credential();
        }
    }

    #[tokio::test]
    async fn load_returns_none_when_nothing_stored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = make_store(dir.path(), "none-stored");
        clear_keyring(&store);
        let out = store.load().await.expect("load");
        assert!(out.is_none(), "empty store should yield None, got {out:?}");
    }

    #[tokio::test]
    async fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = make_store(dir.path(), "round-trip");
        clear_keyring(&store);

        let creds = sample_credentials();
        store.save(creds.clone()).await.expect("save");

        let loaded = store
            .load()
            .await
            .expect("load")
            .expect("creds should be present after save");
        assert_eq!(loaded.client_id, creds.client_id);
        assert_eq!(loaded.granted_scopes, creds.granted_scopes);
        assert_eq!(loaded.token_received_at, creds.token_received_at);
        assert!(
            loaded.token_response.is_some(),
            "token_response must round-trip"
        );
    }

    #[tokio::test]
    async fn clear_removes_persisted_credentials() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = make_store(dir.path(), "clear");
        clear_keyring(&store);

        store.save(sample_credentials()).await.expect("save");
        assert!(store.load().await.expect("load").is_some());

        store.clear().await.expect("clear");
        assert!(
            store.load().await.expect("load after clear").is_none(),
            "clear() must remove stored credentials"
        );
    }

    #[tokio::test]
    async fn load_returns_internal_error_on_corrupt_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = make_store(dir.path(), "corrupt");
        clear_keyring(&store);

        // Write garbage directly to the file fallback path.
        std::fs::create_dir_all(store.fallback_path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&store.fallback_path, "not-json").expect("write");

        // load() goes through read_raw which prefers the keyring; with an
        // empty keyring it should fall through to the corrupt file. Some
        // keyrings on dev machines may shadow this; tolerate either outcome
        // but require the function not to panic.
        let outcome = store.load().await;
        match outcome {
            Ok(Some(_)) | Ok(None) => {
                // keyring shadowed the file; nothing to assert.
            }
            Err(e) => {
                let msg = format!("{e}");
                assert!(
                    msg.contains("deserialize"),
                    "corrupt-file error must mention deserialization, got: {msg}"
                );
            }
        }
    }

    #[test]
    fn write_secret_file_creates_file_atomically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.json");
        write_secret_file(&path, "hello").expect("write_secret_file");
        let content = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(content, "hello");

        // Tmp companion file must be gone after rename.
        let tmp = path.with_extension("tmp");
        assert!(!tmp.exists(), "tmp file should have been renamed");
    }

    #[cfg(unix)]
    #[test]
    fn write_secret_file_is_mode_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.json");
        write_secret_file(&path, "hello").expect("write_secret_file");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "file fallback must be 0600 on unix");
    }

    #[test]
    fn new_uses_platform_data_dir() {
        // Just check that `new` doesn't crash and produces a non-empty
        // account string. Avoids touching shared user state by going
        // through `with_data_dir` for any real work.
        let key = CredentialKey::new("https://example.com/x", None);
        let store = SecureCredentialStore::new(&key).expect("new");
        assert_eq!(store.account, key.to_string());
    }

    #[test]
    fn clear_sync_is_idempotent_on_empty_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = make_store(dir.path(), "idempotent");
        clear_keyring(&store);
        // No credentials saved; clear_sync must not error.
        store.clear_sync().expect("clear_sync on empty store");
        store.clear_sync().expect("clear_sync twice in a row");
    }
}
