//! Tool name filtering for the local→remote proxy.
//!
//! Some upstream MCP servers publish a large catalog of tools, much of which
//! is irrelevant in any given client environment. Servers that don't offer
//! their own filtering knob force every connected client to pay the prompt
//! cost and risk surface of the full tool list. This module gives the user a
//! pair of CLI-driven filters — `--allow-tool` and `--deny-tool` — that
//! `ProxyHandler` consults on both `list_tools` and `call_tool` to hide
//! and refuse unwanted tools.
//!
//! ## Semantics
//!
//! Filtering is purely **subtractive**: with no flags set, the filter is a
//! no-op and every tool the remote advertises passes through. When flags
//! are present:
//!
//! * If **any** `--allow-tool` patterns are supplied, only tools whose name
//!   matches at least one of them are eligible to pass.
//! * Then, any `--deny-tool` match removes the tool from the result.
//!
//! "Deny beats allow" — `--allow-tool 'read_*' --deny-tool 'read_secrets'`
//! does what you'd expect.
//!
//! ## Patterns
//!
//! Patterns are **globs**, not regex (`*` matches anything inside a name,
//! `?` matches one character, `[abc]` character classes work, etc.). Tool
//! names are matched verbatim against each glob. This is intentional:
//! regex would force users to remember to anchor and escape, which is a
//! footgun for a security-adjacent feature. Real-world tool names contain
//! `.` and `_` separators (`github.repos.create`, `read_file`), which globs
//! handle naturally.
//!
//! ## Enforcement points
//!
//! Both `list_tools` (so the local client never sees filtered tools) **and**
//! `call_tool` (so a client that cached an earlier listing, or that follows
//! a server advertising `listChanged: false`, still can't invoke them).
//! Filtering only one of the two would leak the bypass.

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};

/// Compiled allow/deny patterns applied to tool names.
///
/// Construct via [`ToolFilter::from_cli`] from the raw repeatable CLI
/// values, then call [`ToolFilter::permits`] on each tool name. Build the
/// filter once at startup; it is `Send + Sync` and cheap to share.
#[derive(Debug, Clone)]
pub struct ToolFilter {
    /// `None` means "allow-list not configured" (admit any name that isn't
    /// explicitly denied). `Some(_)` always represents at least one user-
    /// supplied pattern — we never construct an empty allow set.
    allow: Option<GlobSet>,
    /// Always present; an empty set denies nothing, which keeps the hot
    /// path branch-free.
    deny: GlobSet,
    /// `true` only when neither flag was provided, used by callers to skip
    /// the per-tool walk in the common case.
    is_noop: bool,
}

impl ToolFilter {
    /// Build a filter from the raw repeatable CLI arguments.
    ///
    /// Each entry of `allow` and `deny` is split on commas so users may pass
    /// either `--allow-tool 'a,b'` or `--allow-tool a --allow-tool b`
    /// interchangeably — this matches the `--scope` ergonomics elsewhere in
    /// the CLI.
    ///
    /// Empty entries (e.g. from trailing commas or all-whitespace values)
    /// are silently skipped rather than rejected, because the surrounding
    /// shell quoting is the more common source of stray empties and an
    /// error here would be more confusing than helpful.
    pub fn from_cli(allow: &[String], deny: &[String]) -> Result<Self> {
        let allow_set = build_set(allow, "--allow-tool")?;
        let deny_set = build_set(deny, "--deny-tool")?.unwrap_or_else(GlobSet::empty);

        let is_noop = allow_set.is_none() && deny_set.is_empty();

        Ok(Self {
            allow: allow_set,
            deny: deny_set,
            is_noop,
        })
    }

    /// A filter that admits every tool. Useful for tests and for the common
    /// path where the user supplied no filtering flags.
    pub fn allow_all() -> Self {
        Self {
            allow: None,
            deny: GlobSet::empty(),
            is_noop: true,
        }
    }

    /// Does this filter let `name` through?
    ///
    /// Order of operations: a name passes if (a) no allow-list is set OR
    /// the allow-list matches, AND (b) the deny-list does not match. This
    /// is the "deny beats allow" semantic documented at the module level.
    pub fn permits(&self, name: &str) -> bool {
        if self.is_noop {
            return true;
        }
        let allowed = match &self.allow {
            Some(set) => set.is_match(name),
            None => true,
        };
        allowed && !self.deny.is_match(name)
    }

    /// `true` when no filtering flags were supplied, so callers can short-
    /// circuit the per-tool retain loop on every `list_tools` response.
    pub fn is_noop(&self) -> bool {
        self.is_noop
    }
}

impl Default for ToolFilter {
    fn default() -> Self {
        Self::allow_all()
    }
}

/// Compile a repeated CLI value (each of which may itself be comma-split)
/// into a single [`GlobSet`]. Returns `None` when the resulting set would
/// be empty so callers can distinguish "user didn't configure this" from
/// "user configured an empty list" (the latter is currently impossible to
/// express but we want the distinction to be explicit at the type level).
fn build_set(raw: &[String], flag: &str) -> Result<Option<GlobSet>> {
    let mut builder = GlobSetBuilder::new();
    let mut count = 0usize;

    for entry in raw {
        for piece in entry.split(',') {
            let pattern = piece.trim();
            if pattern.is_empty() {
                continue;
            }
            let glob = Glob::new(pattern)
                .with_context(|| format!("{flag}: invalid glob pattern {pattern:?}"))?;
            builder.add(glob);
            count += 1;
        }
    }

    if count == 0 {
        return Ok(None);
    }

    let set = builder
        .build()
        .with_context(|| format!("{flag}: failed to compile glob set"))?;
    Ok(Some(set))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(p: &[&str]) -> Vec<String> {
        p.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn noop_filter_admits_everything() {
        let f = ToolFilter::from_cli(&[], &[]).expect("build");
        assert!(f.is_noop());
        assert!(f.permits("anything"));
        assert!(f.permits(""));
        assert!(f.permits("github.repos.create"));
    }

    #[test]
    fn allow_all_constructor_matches_noop() {
        let f = ToolFilter::allow_all();
        assert!(f.is_noop());
        assert!(f.permits("x"));
    }

    #[test]
    fn allow_list_is_exclusive() {
        let f = ToolFilter::from_cli(&allow(&["read_*", "search"]), &[]).expect("build");
        assert!(!f.is_noop());
        assert!(f.permits("read_file"));
        assert!(f.permits("read_anything"));
        assert!(f.permits("search"));
        assert!(!f.permits("write_file"));
        assert!(!f.permits("searchx"));
    }

    #[test]
    fn deny_list_subtracts_from_allow_all() {
        let f = ToolFilter::from_cli(&[], &allow(&["dangerous_*"])).expect("build");
        assert!(!f.is_noop());
        assert!(f.permits("read_file"));
        assert!(!f.permits("dangerous_thing"));
    }

    #[test]
    fn deny_beats_allow() {
        // The motivating example from the module docs.
        let f =
            ToolFilter::from_cli(&allow(&["read_*"]), &allow(&["read_secrets"])).expect("build");
        assert!(f.permits("read_file"));
        assert!(!f.permits("read_secrets"));
        // Not in the allow-list either way.
        assert!(!f.permits("write_file"));
    }

    #[test]
    fn comma_split_is_equivalent_to_repeated_flags() {
        let comma = ToolFilter::from_cli(&allow(&["a,b,c"]), &[]).expect("build");
        let repeated = ToolFilter::from_cli(&allow(&["a", "b", "c"]), &[]).expect("build");
        for name in ["a", "b", "c", "d"] {
            assert_eq!(
                comma.permits(name),
                repeated.permits(name),
                "comma vs repeated must agree on {name}"
            );
        }
    }

    #[test]
    fn whitespace_and_empty_entries_are_ignored() {
        // Trailing commas, stray spaces, and an entirely blank repeat
        // should all degenerate gracefully rather than erroring.
        let f =
            ToolFilter::from_cli(&allow(&[" read_* , ", "", "  ,write_*"]), &[]).expect("build");
        assert!(f.permits("read_file"));
        assert!(f.permits("write_file"));
        assert!(!f.permits("delete_file"));
    }

    #[test]
    fn all_empty_input_is_noop_not_lockout() {
        // A user who passes `--allow-tool ""` (e.g. a templated config that
        // resolved to empty) must not accidentally hide every tool. The
        // only way to lock everything out is to supply a pattern that
        // matches nothing — which is a deliberate user choice.
        let f = ToolFilter::from_cli(&allow(&["", " , "]), &allow(&[""])).expect("build");
        assert!(f.is_noop(), "all-empty input must degrade to no-op");
        assert!(f.permits("anything"));
    }

    #[test]
    fn invalid_glob_is_rejected_with_flag_name() {
        // `[` opens an unterminated character class in globset — a clear
        // syntactic error that should surface to the user, not panic.
        let err =
            ToolFilter::from_cli(&allow(&["read_["]), &[]).expect_err("malformed glob must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--allow-tool"),
            "error must mention the offending flag; got: {msg}"
        );
    }

    #[test]
    fn deny_only_with_no_match_is_no_op_in_practice() {
        // A deny-only filter with no allow-list must still let unrelated
        // tools through (it's not implicitly an allow-list).
        let f = ToolFilter::from_cli(&[], &allow(&["nope_*"])).expect("build");
        assert!(!f.is_noop()); // a real deny set exists
        assert!(f.permits("read_file"));
        assert!(!f.permits("nope_this"));
    }

    #[test]
    fn glob_question_mark_and_classes_work() {
        let f = ToolFilter::from_cli(&allow(&["tool_?", "x[0-9]"]), &[]).expect("build");
        assert!(f.permits("tool_a"));
        assert!(!f.permits("tool_ab"));
        assert!(f.permits("x3"));
        assert!(!f.permits("xa"));
    }
}
