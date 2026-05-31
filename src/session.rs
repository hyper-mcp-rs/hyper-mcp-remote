//! Session identity: a stable hash of the proxy configuration.
//!
//! Two `hyper-mcp-remote` invocations point at the "same" remote session if
//! and only if they share a server URL, optional OAuth resource, and the same
//! set of custom HTTP headers. Each such (configuration) triplet is reduced
//! to a short hex hash that is used as:
//!
//! * the keyring entry name under which tokens are stored;
//! * the per-session filename when falling back to file storage;
//! * a logging field that's safe to print without leaking secrets.
//!
//! The header values are part of the hash so that, e.g., adding a custom
//! `Authorization` header to a server invalidates any tokens that were
//! obtained without it.

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
}
