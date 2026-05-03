# AGENTS.md — Gitway

Guidelines for AI agents working in this codebase.

## Rust coding conventions

- Follow the **Steelbore Rust Guidelines** (invoke `/rust-guidelines` skill before
  any Rust edit).
- All new Rust files must begin with `// SPDX-License-Identifier: GPL-3.0-or-later`.
- All public types must implement `Debug` (derive or custom).
- Use `#[expect(..., reason = "...")]` instead of `#[allow(...)]` for lint suppression.
- Comments must be in American English.
- Passphrase-holding strings must always use `Zeroizing<String>`.

## Forbidden patterns

- **No `unsafe` code.** The workspace enforces `#![forbid(unsafe_code)]`.
- **No `from_utf8_lossy` on passphrase data** — use `from_utf8` and return an error
  on non-UTF-8 output.
- **No relative `SSH_ASKPASS` paths** — the code already enforces absolute paths;
  do not relax this check.
- **No new panic sites** unless the invariant is genuinely unreachable (document why).
- **No TOFU (Trust On First Use)** for host key verification of known providers.

## How to add a new Git hosting provider

The fingerprint table, `GitwayConfig` constructors, and `fingerprints_for_host`
match arms all live in [Steelbore/Anvil](https://github.com/Steelbore/Anvil)
(the extracted SSH stack, published as `anvil-ssh`).  The Gitway-side change is
limited to the agent-facing `describe` advertisement.

In Anvil:

1. Find the provider's official SSH host key fingerprint documentation page.
2. Add `const DEFAULT_<PROVIDER>_HOST: &str` and `const <PROVIDER>_FINGERPRINTS`
   to `src/hostkey.rs`.
3. Add a `fingerprints_for_host` match arm covering the new host constant.
4. Add a `GitwayConfig::<provider>()` convenience constructor in `src/config.rs`.
5. Add tests for the new provider in `hostkey.rs`.
6. Update Anvil's `CLAUDE.md` with the new fingerprint rotation URL.
7. Cut a new `anvil-ssh` minor release.

Then in Gitway:

8. Bump the `anvil-ssh` pin in this workspace's root `Cargo.toml`.
9. Update the `providers` list in `run_describe()` in `gitway-cli/src/main.rs`
   so the new provider appears in `gitway describe --json`.

## How to run integration tests

Integration tests that hit real servers are gated behind the `integration` feature
and are not run by default.  To run them:

```sh
nix-shell --run 'cargo test --workspace --features integration 2>&1'
```

These tests require network access and valid SSH credentials.

## Structured output rules (SFRS)

- `--test` and `--install` emit JSON when `--json` / `--format json` is set, or
  when `AI_AGENT=1`, `AGENT=1`, `CI=true`, or stdout is not a terminal.
- `schema` and `describe` always emit JSON to stdout.
- Errors in JSON mode go to **stderr** as `{"error": {"code": "...", ...}}`.
- Exit codes: 0=success, 1=general, 2=usage, 3=not-found, 4=permission-denied.
- The exec path (normal git relay) never emits JSON to stdout — stdout carries
  binary git-pack data.

## Dependency policy

- No new crates without discussion.  The dependency tree is intentionally narrow.
- `serde` (with derive) is intentionally absent — JSON output uses `serde_json::json!()`.
- `chrono` and `time` are intentionally absent — ISO 8601 timestamps use the
  dependency-free `epoch_secs_to_iso8601` function in `main.rs`.
- Do not switch the russh crypto backend from `aws-lc-rs` to `ring`.
