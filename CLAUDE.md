# CLAUDE.md — Gitway

Gitway is a pure-Rust SSH toolkit for Git: transport, keys, signing, agent.
It replaces the general-purpose `ssh` binary in the Git transport pipeline,
plus the subset of `ssh-keygen`, `ssh-add`, and `ssh-agent` that day-to-day
Git workflows need.  Works against GitHub, GitLab, Codeberg, AUR, sourcehut,
and self-hosted Git instances.

## Workspace layout

```
gitway-lib/   Core SSH transport library (pub API, no CLI concerns)
gitway-cli/   Binary crate — argument parsing, passphrase prompting, output formatting
packaging/    AUR PKGBUILDs, packaging notes
docs/         PRD, Plan, PDF collateral
.github/      CI and release workflows
flake.nix     Nix flake (build + devShell)
shell.nix     Standalone Nix dev shell (no flake lock needed)
```

## Build and test

```sh
# All targets
nix-shell --run 'cargo build --release 2>&1'

# Tests only
nix-shell --run 'cargo test --workspace 2>&1'

# Lint
nix-shell --run 'cargo clippy --workspace -- -D warnings 2>&1'

# Format check
nix-shell --run 'cargo fmt --check 2>&1'
```

`musl-tools` is needed for the static Linux target used in release CI:
```sh
sudo apt-get install -y musl-tools
cargo build --release --target x86_64-unknown-linux-musl -p gitway
```

## Key invariants

- **`#![forbid(unsafe_code)]`** — no unsafe in any project-owned crate.
- **Pinned host keys** — SHA-256 fingerprints for GitHub, GitLab, and Codeberg
  are embedded in `gitway-lib/src/hostkey.rs`.  Update them by fetching the
  official fingerprint pages and running `cargo test` to verify.
- **stdout stays clean** — all diagnostic output goes to stderr.  stdout is
  reserved for either binary git-pack data (exec path) or machine-readable JSON
  (`--json` / `--format json`).
- **Passphrase zeroization** — any `String` holding a passphrase must be wrapped
  in `Zeroizing<String>` (from the `zeroize` crate) so bytes are overwritten
  before deallocation.
- **Exit codes** (SFRS Rule 2):
  - 0 — success
  - 1 — general / unexpected error
  - 2 — usage error (bad arguments, invalid configuration)
  - 3 — not found (no key, unknown host)
  - 4 — permission denied (auth failed, host key mismatch)

## SSH fingerprint rotation procedure

When a hosting provider rotates its host key:
1. Fetch the new fingerprint from the provider's official documentation page.
2. Update the constant in `gitway-lib/src/hostkey.rs`.
3. Run `cargo test --workspace` to ensure the embedded tests still pass.
4. Open a PR; the CI pipeline will validate all targets.

Provider fingerprint pages:
- GitHub: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
- GitLab: https://docs.gitlab.com/ee/user/gitlab_com/#ssh-host-keys-fingerprints
- Codeberg: https://codeberg.org/Codeberg/Community/issues/1192

## Security invariants

- `SSH_ASKPASS` must be an absolute path (enforced in `try_askpass`).
- World-writable `SSH_ASKPASS` programs are rejected on Unix.
- `from_utf8_lossy` is forbidden on passphrase data; use `from_utf8` and reject
  non-UTF-8 output.
- The raw stdout buffer from `SSH_ASKPASS` is zeroized on every exit path
  (success, error, and early return).

## Crypto backend

russh is configured with the `aws-lc-rs` backend (non-FIPS, no CMake needed).
Do not switch to `ring` — `aws-lc-rs` provides post-quantum algorithm support
that `ring` lacks.  On Windows, `nasm` is required for the build (handled in CI).

## Dual-mode output (SFRS)

Gitway implements the Steelbore Dual-Mode CLI SFRS:
- `--json` / `--format json`: structured JSON on stdout for `--test` and `--install`.
- `schema` / `describe` subcommands: always JSON, for agent/CI discovery.
- Agent env detection: `AI_AGENT=1`, `AGENT=1`, `CI=true` → JSON mode.
- `--no-color` / `NO_COLOR`: respected (no ANSI codes are emitted regardless).
- Error output in JSON mode goes to stderr as `{"error":{...}}`.
