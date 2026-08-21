# Contributing to hyper-mcp-remote

Thanks for your interest in contributing! Issues and pull requests are
welcome. This document covers everything you need to get a change from your
machine into `main`.

## Prerequisites

- **Rust** — the toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml)
  (currently `1.97`, with `clippy` and `rustfmt`). If you use `rustup`, the
  correct version is selected automatically.
- **[lefthook](https://lefthook.dev)** — manages the git hooks. Install it via
  your package manager (e.g. `brew install lefthook`).
- **[cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)** and the
  `llvm-tools-preview` component — used by the pre-push hook to enforce test
  coverage:

  ```sh
  rustup component add llvm-tools-preview
  cargo install cargo-llvm-cov --locked
  ```

- **[cargo-audit](https://github.com/rustsec/rustsec)** and
  **[cargo-deny](https://embarkstudios.github.io/cargo-deny/)** — only needed
  if your change touches `Cargo.toml`, `Cargo.lock`, or `deny.toml`:

  ```sh
  cargo install cargo-audit --locked
  cargo install cargo-deny --locked
  ```

## Getting set up

```sh
git clone https://github.com/hyper-mcp-rs/hyper-mcp-remote.git
cd hyper-mcp-remote
lefthook install   # once per clone — wires up pre-commit and pre-push hooks
```

## Building and testing

```sh
cargo build
cargo test                                              # unit + offline integration tests
cargo test --test e2e_gitlab -- --ignored --nocapture   # live OAuth against gitlab.com
```

The e2e test spawns the compiled binary and drives it through a child-process
MCP client, exactly the way Claude Desktop or Zed do. It is `#[ignore]`d
because it requires network access and (on first run) human interaction in a
browser. You don't need to run it for most changes — CI does not run it
either — but please run it if you touch the OAuth or transport code.

## Testing requirements

**Unit tests are mandatory for new functionality.** Every new feature,
module, or non-trivial change must be accompanied by tests. Tests live inline
with the production code (`#[cfg(test)]` modules), following the existing
style in `src/`.

The pre-push hook enforces a **minimum of 70% line coverage** across the
workspace. Reproduce the check locally with:

```sh
cargo llvm-cov --workspace --locked --fail-under-lines 70
```

For a browsable HTML report of which lines are uncovered:

```sh
cargo llvm-cov --workspace --html --open
```

## Code style

Formatting and linting are enforced by the pre-commit hook and by CI:

```sh
cargo fmt --all
cargo clippy --all-targets --all-features --locked -- -D warnings
```

Clippy warnings are errors. Fix them, or add a `#[allow(...)]` with a comment
justifying it.

## Git hooks

Hooks are managed by [`lefthook.yml`](lefthook.yml):

| Hook       | What runs                                                        |
| ---------- | ---------------------------------------------------------------- |
| pre-commit | `cargo fmt --check`, `cargo clippy` (fast feedback)              |
| pre-push   | full test suite with coverage gate; `cargo audit` and `cargo deny check` when dependency manifests changed |

**Never bypass the hooks** (`--no-verify`). If a hook fails, fix the
underlying problem before committing or pushing. You can override hook
behavior locally without touching the shared config by creating a
`lefthook-local.yml` (gitignored).

## Commits

- **Sign off every commit** with `git commit -s`. This adds a
  `Signed-off-by:` trailer certifying you have the right to submit the change.
- Keep commits focused; separate refactors from behavior changes where
  practical.
- Write commit messages that explain *why*, not just *what*.

## Submitting a pull request

1. Fork the repository and create a branch from `main`.
2. Make your change, including tests and any relevant documentation updates
   (`README.md`, doc comments).
3. Make sure the full local gauntlet passes:

   ```sh
   cargo fmt --all -- --check
   cargo clippy --all-targets --all-features --locked -- -D warnings
   cargo llvm-cov --workspace --locked --fail-under-lines 70
   ```

4. Open a PR against `main`. CI runs formatting, clippy, tests with coverage,
   and SBOM generation — all jobs must pass before merge.

If your change touches dependencies, expect `cargo audit` and
`cargo deny check` to run on push. Justify any additions to `deny.toml` with
a comment.

## Project layout

See the [Project layout](README.md#project-layout) section of the README for
a map of the source tree, and [How it works](README.md#how-it-works) for an
overview of the proxy and OAuth flow.

## Reporting issues

When filing a bug, please include:

- The `hyper-mcp-remote` version (`hyper-mcp-remote --version`) and OS.
- The MCP client you're using (Claude Desktop, Zed, Cursor, ...).
- Relevant log output — see the
  [Where things live](README.md#where-things-live) section of the README for
  log file locations. **Scrub tokens and secrets before posting.**

## License

By contributing, you agree that your contributions will be licensed under the
[Apache-2.0](LICENSE) license that covers the project.
