//! Session and credential identities derived from the proxy configuration.
//!
//! This module defines two related-but-distinct identifiers:
//!
//! * [`SessionHash`] — a fingerprint of the full configuration
//!   `(server_url, resource, headers)`. Used for logging so operators can
//!   correlate log lines from the same invocation without leaking secrets.
//!   Two invocations with different headers produce different hashes, which
//!   is desirable in logs but undesirable for credential storage.
//!
//! * [`CredentialKey`] — a stable identifier for the OAuth identity
//!   `(server_url, resource)`. Headers are deliberately excluded so that
//!   request-time header churn (tracing IDs, per-launch `User-Agent`
//!   strings, etc.) does not orphan cached tokens. The URL is lightly
//!   normalized so trivially-equivalent inputs (`HTTPS://Example.com:443/`
//!   vs `https://example.com/`) hash the same. This is what the keyring
//!   entry and file fallback are keyed on, so refresh tokens survive
//!   across launches as long as the user keeps pointing at the same server.

use std::collections::BTreeMap;

use http::{HeaderName, HeaderValue};
use sha2::{Digest, Sha256};

/// A short, stable identifier for a (server, headers, resource) tuple.
///
/// 16 hex chars (64 bits) is more than enough to avoid collisions across the
/// handful of MCP servers a user is likely to proxy at once, while keeping
/// log lines readable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionHash(String);

impl SessionHash {
    /// Compute a hash for this server + headers + resource combination.
    pub fn new(
        server_url: &str,
        resource: Option<&str>,
        headers: &std::collections::HashMap<HeaderName, HeaderValue>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(server_url.as_bytes());
        hasher.update(b"|");
        if let Some(r) = resource {
            hasher.update(r.as_bytes());
        }
        hasher.update(b"|");

        // BTreeMap so that key order is deterministic regardless of how the
        // HashMap was populated. Bytes-only because not all HeaderValues are
        // valid UTF-8.
        let sorted: BTreeMap<&str, &[u8]> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_bytes()))
            .collect();
        for (name, value) in sorted {
            hasher.update(name.as_bytes());
            hasher.update(b":");
            hasher.update(value);
            hasher.update(b"\n");
        }

        let digest = hasher.finalize();
        // First 8 bytes -> 16 hex chars is plenty.
        SessionHash(hex::encode(&digest[..8]))
    }

    #[allow(dead_code)] // exposed for callers that want the bare hash string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Stable identifier for an OAuth identity, derived from
/// `(server_url, resource)` only.
///
/// Unlike [`SessionHash`], headers are not part of the hash; this is the
/// identifier used to key persistent credential storage so that incidental
/// header changes between launches don't orphan cached refresh tokens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredentialKey(String);

impl CredentialKey {
    /// Compute the key for this `(server_url, resource)` pair.
    ///
    /// If `server_url` parses as a URL we normalize it (lowercase scheme
    /// and host, drop default port, strip query/fragment, collapse trailing
    /// slashes) before hashing. If it doesn't parse, we hash the raw
    /// string; callers validate the URL up front via the CLI layer, so this
    /// path is only hit in tests with intentionally bogus inputs.
    pub fn new(server_url: &str, resource: Option<&str>) -> Self {
        let normalized = normalize_server_url(server_url);
        let mut hasher = Sha256::new();
        hasher.update(normalized.as_bytes());
        hasher.update(b"|");
        if let Some(r) = resource {
            hasher.update(r.as_bytes());
        }
        let digest = hasher.finalize();
        CredentialKey(hex::encode(&digest[..8]))
    }

    #[allow(dead_code)] // exposed for callers that want the bare hash string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CredentialKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lightly normalize a server URL for credential-key purposes.
///
/// We intentionally do *not* perform aggressive canonicalization (e.g.
/// percent-decoding, dot-segment removal beyond what `url` already does):
/// the goal is only to absorb trivial whitespace/case differences in how
/// the user typed the same server URL across launches. If parsing fails we
/// fall back to the raw input so the function is total.
fn normalize_server_url(raw: &str) -> String {
    let trimmed = raw.trim();
    let Ok(mut u) = url::Url::parse(trimmed) else {
        return trimmed.to_string();
    };

    u.set_query(None);
    u.set_fragment(None);

    // `url` already lowercases the scheme and host on parse, but be
    // explicit about removing default ports so `:443` and the implicit
    // port collapse.
    if let Some(port) = u.port() {
        let default = match u.scheme() {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        };
        if Some(port) == default {
            let _ = u.set_port(None);
        }
    }

    // Collapse trailing slashes so `/mcp` and `/mcp/` are equivalent, but
    // preserve a bare `/` root so `https://example.com` and
    // `https://example.com/` still match.
    let new_path = {
        let path = u.path();
        let trimmed_path = path.trim_end_matches('/');
        if trimmed_path.is_empty() {
            "/".to_string()
        } else {
            trimmed_path.to_string()
        }
    };
    if new_path != u.path() {
        u.set_path(&new_path);
    }

    u.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty() -> HashMap<HeaderName, HeaderValue> {
        HashMap::new()
    }

    #[test]
    fn deterministic() {
        let a = SessionHash::new("https://example.com/mcp", None, &empty());
        let b = SessionHash::new("https://example.com/mcp", None, &empty());
        assert_eq!(a, b);
    }

    #[test]
    fn differs_on_resource() {
        let a = SessionHash::new("https://example.com/mcp", None, &empty());
        let b = SessionHash::new("https://example.com/mcp", Some("tenant-1"), &empty());
        assert_ne!(a, b);
    }

    #[test]
    fn differs_on_headers() {
        let mut h = HashMap::new();
        h.insert(
            HeaderName::from_static("x-foo"),
            HeaderValue::from_static("bar"),
        );
        let a = SessionHash::new("https://example.com/mcp", None, &empty());
        let b = SessionHash::new("https://example.com/mcp", None, &h);
        assert_ne!(a, b);
    }

    #[test]
    fn header_order_does_not_matter() {
        let mut h1 = HashMap::new();
        h1.insert(
            HeaderName::from_static("x-a"),
            HeaderValue::from_static("1"),
        );
        h1.insert(
            HeaderName::from_static("x-b"),
            HeaderValue::from_static("2"),
        );

        let mut h2 = HashMap::new();
        h2.insert(
            HeaderName::from_static("x-b"),
            HeaderValue::from_static("2"),
        );
        h2.insert(
            HeaderName::from_static("x-a"),
            HeaderValue::from_static("1"),
        );

        let a = SessionHash::new("https://example.com/mcp", None, &h1);
        let b = SessionHash::new("https://example.com/mcp", None, &h2);
        assert_eq!(a, b);
    }

    #[test]
    fn hex_length_is_sixteen() {
        let h = SessionHash::new("https://example.com/mcp", None, &empty());
        assert_eq!(h.as_str().len(), 16);
        assert!(h.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    // --- CredentialKey ---

    #[test]
    fn credential_key_is_deterministic() {
        let a = CredentialKey::new("https://example.com/mcp", None);
        let b = CredentialKey::new("https://example.com/mcp", None);
        assert_eq!(a, b);
    }

    #[test]
    fn credential_key_ignores_headers() {
        // CredentialKey doesn't take headers at all; the regression we care
        // about is that two SessionHashes that differ only in headers map
        // to the *same* CredentialKey.
        let mut h = HashMap::new();
        h.insert(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_static("abc"),
        );
        let s1 = SessionHash::new("https://example.com/mcp", None, &empty());
        let s2 = SessionHash::new("https://example.com/mcp", None, &h);
        assert_ne!(s1, s2, "sanity: SessionHash still differs on headers");

        let k1 = CredentialKey::new("https://example.com/mcp", None);
        let k2 = CredentialKey::new("https://example.com/mcp", None);
        assert_eq!(k1, k2);
    }

    #[test]
    fn credential_key_differs_on_resource() {
        let a = CredentialKey::new("https://example.com/mcp", None);
        let b = CredentialKey::new("https://example.com/mcp", Some("tenant-1"));
        assert_ne!(a, b);
    }

    #[test]
    fn credential_key_normalizes_trivial_url_variants() {
        // Default port, trailing slash, host case, query/fragment noise
        // should all collapse to the same key.
        let canonical = CredentialKey::new("https://example.com/mcp", None);

        for variant in [
            "https://example.com/mcp/",
            "https://example.com:443/mcp",
            "https://Example.com/mcp",
            "https://example.com/mcp?ignored=1",
            "https://example.com/mcp#frag",
            "  https://example.com/mcp  ",
        ] {
            assert_eq!(
                CredentialKey::new(variant, None),
                canonical,
                "variant {variant:?} should normalize to canonical form"
            );
        }
    }

    #[test]
    fn credential_key_differs_on_path() {
        let a = CredentialKey::new("https://example.com/mcp", None);
        let b = CredentialKey::new("https://example.com/other", None);
        assert_ne!(a, b);
    }

    #[test]
    fn credential_key_falls_back_on_unparseable_input() {
        // Doesn't parse as a URL, but the function must still be total.
        let a = CredentialKey::new("not a url", None);
        let b = CredentialKey::new("not a url", None);
        assert_eq!(a, b);
        assert_eq!(a.as_str().len(), 16);
    }

    #[test]
    fn credential_key_hex_length_is_sixteen() {
        let k = CredentialKey::new("https://example.com/mcp", None);
        assert_eq!(k.as_str().len(), 16);
        assert!(k.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }
}
