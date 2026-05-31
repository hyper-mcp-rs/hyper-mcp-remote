//! HTTP header parsing and `${ENV}` interpolation.
//!
//! Headers are accepted on the command line as `Name: value`. Values may
//! contain `${VAR}` placeholders that are interpolated from the process
//! environment at startup (so secrets can be passed via the MCP client's
//! `env:` block rather than embedded in the args).

use std::collections::HashMap;

use anyhow::{Context, Result};
use http::{HeaderName, HeaderValue};

/// Parses `--header "Name: value"` strings into a header map, expanding
/// `${ENV_VAR}` references from `std::env`.
///
/// Unknown environment variables are replaced with an empty string and a
/// warning is logged, matching the behavior of upstream `mcp-remote`.
pub fn parse(raw: &[String]) -> Result<HashMap<HeaderName, HeaderValue>> {
    let mut out = HashMap::new();
    for entry in raw {
        let (name, value) = entry
            .split_once(':')
            .with_context(|| format!("invalid header '{entry}', expected 'Name: value'"))?;

        let name = name.trim();
        let value = value.trim();

        if name.is_empty() {
            anyhow::bail!("invalid header '{entry}': empty name");
        }

        let expanded = expand_env_vars(value);
        let header_name =
            HeaderName::try_from(name).with_context(|| format!("invalid header name '{name}'"))?;
        let header_value = HeaderValue::try_from(expanded.as_str())
            .with_context(|| format!("invalid header value for '{name}'"))?;
        out.insert(header_name, header_value);
    }
    Ok(out)
}

/// Replace every `${NAME}` in `s` with the value of the env var `NAME`.
/// Missing variables expand to an empty string with a warning.
fn expand_env_vars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) => {
                let var = &after[..end];
                match std::env::var(var) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => {
                        tracing::warn!(var, "environment variable referenced in header not set");
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                // No closing brace; emit the rest verbatim and stop.
                out.push_str("${");
                out.push_str(after);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_header() {
        let map = parse(&["X-Foo: bar".to_string()]).expect("parse");
        let key = HeaderName::from_static("x-foo");
        assert_eq!(
            map.get(&key)
                .expect("x-foo header must be present")
                .to_str()
                .expect("x-foo value must be valid UTF-8"),
            "bar"
        );
    }

    #[test]
    fn rejects_missing_colon() {
        let err = parse(&["nope".to_string()]).expect_err("missing colon must fail");
        assert!(err.to_string().contains("invalid header"));
    }

    #[test]
    fn expands_env_var() {
        // SAFETY: tests run in a single process; we only mutate a unique var.
        unsafe { std::env::set_var("HYPER_MCP_TEST_TOKEN", "secret-123") };
        let map = parse(&["Authorization: Bearer ${HYPER_MCP_TEST_TOKEN}".to_string()])
            .expect("parse with env var");
        assert_eq!(
            map.get(&HeaderName::from_static("authorization"))
                .expect("authorization header must be present")
                .to_str()
                .expect("authorization value must be valid UTF-8"),
            "Bearer secret-123"
        );
        unsafe { std::env::remove_var("HYPER_MCP_TEST_TOKEN") };
    }

    #[test]
    fn unterminated_env_var_is_left_verbatim() {
        let out = expand_env_vars("hello ${UNCLOSED");
        assert_eq!(out, "hello ${UNCLOSED");
    }
}
