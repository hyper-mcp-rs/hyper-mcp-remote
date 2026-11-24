//! A non-validating peek at the `exp` claim of a JWT-shaped access token.
//!
//! Access tokens are opaque to OAuth clients by contract, and we never
//! rely on one being a JWT. But when a server *does* hand out JWTs (Entra
//! ID, Auth0, Keycloak, ...), the token's own `exp` is the one statement
//! about its lifetime that cannot be corrupted by anything on our side:
//! unlike `token_received_at` in the credential cache, it is signed by the
//! issuer and travels with the token. [`cached_access_token_is_stale`]
//! consults it as an extra vote for "refresh now".
//!
//! Nothing here verifies signatures or any other claim; a token that
//! merely looks like a JWT is only ever used to refresh *earlier*, which
//! is harmless if the guess is wrong.
//!
//! [`cached_access_token_is_stale`]: super::cached_access_token_is_stale

/// Return the `exp` claim (seconds since the UNIX epoch) of `token` if it
/// has the three-part `header.payload.signature` shape of a JWS compact
/// serialization and its payload is a JSON object with a numeric `exp`.
///
/// `None` for anything else: opaque tokens, malformed base64, payloads
/// without `exp`, or a non-numeric `exp`.
pub(crate) fn exp_claim(token: &str) -> Option<u64> {
    let mut parts = token.split('.');
    let (_header, payload, _signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let bytes = base64url_decode(payload)?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let exp = claims.as_object()?.get("exp")?;
    // RFC 7519 defines `exp` as a NumericDate, which may carry a
    // fractional part. Truncating to whole seconds is fine for an
    // "about to expire" check.
    exp.as_u64()
        .or_else(|| exp.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64))
}

/// Decode base64 with either the URL-safe (`-_`) or standard (`+/`)
/// alphabet, with or without `=` padding. JWTs use URL-safe without
/// padding, but tokens copied through other tooling occasionally pick up
/// padding, so be lenient. Rejects any other byte.
///
/// Hand-rolled rather than pulling in the `base64` crate: the input is
/// tiny, and the crate is not otherwise a direct dependency.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard base64url without padding, as every JWT library emits.
    fn b64url(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut n: u32 = 0;
            for (i, b) in chunk.iter().enumerate() {
                n |= u32::from(*b) << (16 - 8 * i);
            }
            let chars = chunk.len() + 1;
            for i in 0..chars {
                let idx = ((n >> (18 - 6 * i)) & 0x3F) as usize;
                out.push(ALPHABET[idx] as char);
            }
        }
        out
    }

    fn jwt_with_payload(payload: &serde_json::Value) -> String {
        let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
        let body = b64url(payload.to_string().as_bytes());
        format!("{header}.{body}.signature-is-not-checked")
    }

    // -- exp_claim ----------------------------------------------------------

    #[test]
    fn exp_claim_reads_integer_exp_from_jwt() {
        let token = jwt_with_payload(&serde_json::json!({ "sub": "u", "exp": 1_795_538_449u64 }));
        assert_eq!(exp_claim(&token), Some(1_795_538_449));
    }

    #[test]
    fn exp_claim_truncates_fractional_numeric_date() {
        let token = jwt_with_payload(&serde_json::json!({ "exp": 1_700_000_000.75 }));
        assert_eq!(exp_claim(&token), Some(1_700_000_000));
    }

    #[test]
    fn exp_claim_is_none_for_negative_exp() {
        let token = jwt_with_payload(&serde_json::json!({ "exp": -5 }));
        assert_eq!(exp_claim(&token), None);
    }

    #[test]
    fn exp_claim_is_none_when_payload_has_no_exp() {
        let token = jwt_with_payload(&serde_json::json!({ "sub": "u", "iat": 1 }));
        assert_eq!(exp_claim(&token), None);
    }

    #[test]
    fn exp_claim_is_none_when_exp_is_not_numeric() {
        let token = jwt_with_payload(&serde_json::json!({ "exp": "soon" }));
        assert_eq!(exp_claim(&token), None);
    }

    #[test]
    fn exp_claim_is_none_for_opaque_token() {
        assert_eq!(exp_claim("glpat-3c71dab8c503c7f26b11343e4b42c0db"), None);
        assert_eq!(exp_claim(""), None);
    }

    #[test]
    fn exp_claim_is_none_for_wrong_number_of_segments() {
        let body = b64url(br#"{"exp":1}"#);
        assert_eq!(exp_claim(&format!("h.{body}")), None, "two segments");
        assert_eq!(
            exp_claim(&format!("h.{body}.s.extra")),
            None,
            "four segments"
        );
    }

    #[test]
    fn exp_claim_is_none_for_undecodable_payload() {
        assert_eq!(exp_claim("h.!!not-base64!!.s"), None);
    }

    #[test]
    fn exp_claim_is_none_when_payload_is_not_a_json_object() {
        let body = b64url(b"[1,2,3]");
        assert_eq!(exp_claim(&format!("h.{body}.s")), None);
        let body = b64url(b"not json");
        assert_eq!(exp_claim(&format!("h.{body}.s")), None);
    }

    // -- base64url_decode ---------------------------------------------------

    #[test]
    fn base64url_decode_handles_every_tail_length() {
        // RFC 4648 test vectors, unpadded.
        assert_eq!(base64url_decode("").as_deref(), Some(&b""[..]));
        assert_eq!(base64url_decode("Zg").as_deref(), Some(&b"f"[..]));
        assert_eq!(base64url_decode("Zm8").as_deref(), Some(&b"fo"[..]));
        assert_eq!(base64url_decode("Zm9v").as_deref(), Some(&b"foo"[..]));
        assert_eq!(base64url_decode("Zm9vYg").as_deref(), Some(&b"foob"[..]));
        assert_eq!(base64url_decode("Zm9vYmE").as_deref(), Some(&b"fooba"[..]));
        assert_eq!(
            base64url_decode("Zm9vYmFy").as_deref(),
            Some(&b"foobar"[..])
        );
    }

    #[test]
    fn base64url_decode_tolerates_padding() {
        assert_eq!(base64url_decode("Zg==").as_deref(), Some(&b"f"[..]));
        assert_eq!(base64url_decode("Zm8=").as_deref(), Some(&b"fo"[..]));
    }

    #[test]
    fn base64url_decode_accepts_both_alphabets() {
        // 0xFB 0xFF encodes to "-_8" (url) / "+/8" (standard).
        assert_eq!(
            base64url_decode("-_8").as_deref(),
            Some(&[0xFBu8, 0xFF][..])
        );
        assert_eq!(
            base64url_decode("+/8").as_deref(),
            Some(&[0xFBu8, 0xFF][..])
        );
    }

    #[test]
    fn base64url_decode_rejects_foreign_bytes() {
        assert_eq!(base64url_decode("Zm9v\n"), None);
        assert_eq!(base64url_decode("Zm 9v"), None);
        assert_eq!(base64url_decode("Zm9v!"), None);
    }

    #[test]
    fn base64url_decode_round_trips_a_realistic_payload() {
        let payload = br#"{"aud":"d07ea282","iat":1795533028,"exp":1795538449,"scp":"User.Read"}"#;
        assert_eq!(
            base64url_decode(&b64url(payload)).as_deref(),
            Some(&payload[..])
        );
    }
}
