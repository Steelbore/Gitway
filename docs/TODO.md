# Gitway TODO

## Milestone 1: Proof of Life (Workspace scaffold, `session.rs`, `--test` flag working)

- [✓] Initialize Cargo workspace (`gitway`) with two crates: `gitway-lib` and `gitway-cli`.
- [✓] Set up `Cargo.toml` dependencies (`russh`, `tokio`, `ssh-key`, `clap`, `thiserror`, `log`, etc.).
- [✓] Create CLI entry point (`cli.rs`) and argument parsing using `clap` for all flags defined in PRD (FR-18, 19).
- [✓] Implement `--test` argument logic (FR-21) to verify connection without full relay.
- [✓] Scaffold `session.rs` wrapping `russh::client::Session`.
- [✓] Implement `check_server_key` with pinned GitHub fingerprints (ED25519) (FR-6).
- [✓] Write `tests/test_connection.rs` integration tests running against `github.com`.

## Milestone 2: Full Auth Chain (Key-discovery, passphrase prompting, agent support)

- [✓] Implement identity resolution (flags -> `.ssh` paths -> agent) (FR-9).
- [✓] Integrate SSH Agent connection via `russh-keys`.
- [✓] Implement passphrase prompting using `rpassword` (FR-10).
- [✓] Support RSA SHA-2 signing requirement (FR-11).
- [✓] Allow OpenSSH certificates (FR-12).
- [✓] Write unit tests for the priority order of key discovery.

## Milestone 3: Transport Relay (`relay.rs`, end-to-end `git clone` success)

- [✓] Spawn bidirectional relay tasks for stdout, stdin, and stderr channels (FR-15).
- [✓] Map remote exit codes back to local process, following OpenSSH exit codes (128+signal) (FR-16, 17).
- [✓] Ensure stdin is closed appropriately when Git finishes pushing data.
- [✓] Write `tests/test_clone.rs` integration test using `git clone` with `GIT_SSH_COMMAND=gitway`.

## Milestone 4: CLI Polish (`--install`, GHE support, `--insecure` escape hatch)

- [✓] Add support for `~/.config/gitway/known_hosts` for GHE domains (FR-7).
- [✓] Implement `--insecure-skip-host-check` flag logic (FR-8).
- [✓] Silently ignore unknown `-o` config options (FR-20).
- [✓] Implement `--install` to globally update `core.sshCommand` (FR-22).

## Milestone 5 & 6: Library API & Hardening

- [✓] Expose `GitwaySession`, `GitwayConfig`, `GitwayError` cleanly in `lib.rs` (FR-23, 24).
- [✓] Setup `cargo clippy` and restrict `unwrap`, `expect`, `panic` (NFR-5).
- [✓] Configure `CryptoVec` and secure memory handling (NFR-3).
- [✓] Ensure cold-start connects <= 2s (NFR-1).
- [✓] Finalize the testing suite via CI Actions matrix.

## Milestone 7: Distribution & Publication

- [✓] Write `README.md` for the workspace root (install, usage, library quick-start).
- [✓] Publish `gitway-lib` to crates.io (requires README, categories, `cargo publish --dry-run`).
- [✓] Add tag-triggered GitHub Actions release workflow: build static binaries (Linux x86-64, macOS arm64, Windows x86-64), upload as GitHub Release assets.
- [✓] Extend the CI matrix to macOS and Windows runners.

## Milestone 8: Hardening

- [✓] Verify DSA keys and 3DES ciphers are absent from the russh session config (NFR-6).
- [✓] Run `cargo geiger` and confirm zero `unsafe` blocks in project-owned code (S3).
- [✓] Measure static binary size; document and verify < 10 MB target (S2).
- [✓] Benchmark steady-state throughput against OpenSSH; document result within 5% (NFR-2, S1).
- [✓] Add cargo-fuzz target over connection handshake and key-parsing paths (M6 fuzzing).
- [✓] Validate against Git's transport test suite (`t5500`, `t5516`) (NFR-8, S4).

## Milestone 9: Repository Cleanup & Consolidation

- [✓] Remove stale `Gitway/` duplicate directory.
- [✓] Consolidate documentation into `docs/` (PRD, TODO, IDE_GUIDE).
- [✓] Add `shell.nix` for NixOS dev environment with proper RUSTFLAGS handling.
- [✓] Update workspace `Cargo.toml` to reference crates.io russh dependency.

## Milestone 10: Post-Quantum Cryptography Support

- [✓] Switch from `ring` to `aws-lc-rs` crypto backend for PQC support.
- [✓] Update GitHub SSH fingerprints (GitHub rotated Ed25519 and RSA keys).
- [✓] Verify build works without CMake dependency (non-FIPS aws-lc-rs).
- [✓] Confirm all 25 tests pass with aws-lc-rs backend.
- [✓] Verify binary size remains under 10 MB target (6.6 MB achieved).
- [✓] Fix hostname parsing to strip username (e.g., `git@github.com` → `github.com`).

## Milestone 11: Key generation and SSH signing — Phase 1 of §5.7 (v0.4)

OpenSSH-free key generation and commit signing so `gpg.format=ssh` works without `openssh-clients` installed. Covers PRD §5.7.1 (FR-25..31) and §5.7.2 (FR-32..35).

### Dependencies

- [✓] Add `ssh-key = "0.6.7"` (pure-Rust OpenSSH format + SSHSIG, RustCrypto).
- [✓] Add `sha2 = "0.10"` and `rand_core = "0.6"` workspace deps.

### `gitway-lib` — new modules

- [✓] `gitway-lib/src/keygen.rs` — `KeyType` enum; `generate`, `write_keypair`, `change_passphrase`, `fingerprint`, `extract_public`.
- [✓] `gitway-lib/src/sshsig.rs` — `sign`, `verify`, `check_novalidate`, `find_principals`; `Verified` struct.
- [✓] `gitway-lib/src/allowed_signers.rs` — parser for git's `allowed_signers` file (principals, `namespaces="…"`, `cert-authority`, `!negation`, quoted patterns).
- [✓] Register all three modules in `gitway-lib/src/lib.rs`.

### `GitwayError`

- [✓] Add `Signing { message }` variant → exit 1 / `GENERAL_ERROR`.
- [✓] Add `SignatureInvalid { reason }` variant → exit 4 / `PERMISSION_DENIED`.
- [✓] Update `error_code`, `exit_code`, `hint`, `Display` tables.

### `gitway` CLI (`gitway-cli` binary)

- [✓] Extend `GitwaySubcommand` enum with `Keygen(KeygenArgs)` and `Sign(SignArgs)` plus nested subcommands (`generate`, `fingerprint`, `extract-public`, `change-passphrase`, `sign`, `verify`).
- [✓] Implement `gitway-cli/src/keygen.rs` dispatcher with `--json` support.
- [✓] Implement `gitway-cli/src/sign.rs` dispatcher (top-level alias for `keygen sign`).
- [✓] Wire both into `run()` in `main.rs`; expose `prompt_passphrase`, `now_iso8601`, `emit_json` as `pub(crate)`.
- [✓] Update `run_schema` / `run_describe` JSON manifests to advertise the new verbs and `gitway-keygen` companion binary.

### `gitway-keygen` shim binary (ssh-keygen-compat)

- [✓] Add `[[bin]] name = "gitway-keygen"` to `gitway-cli/Cargo.toml`.
- [✓] Hand-rolled argv parser (not clap) for byte-strict compat: `-t -b -f -N -C -l -y -p -P -Y -n -I -s -E -O`.
- [✓] Dispatch `-Y sign`, `-Y verify`, `-Y check-novalidate`, `-Y find-principals` via `gitway_lib::sshsig`.
- [✓] Dispatch keygen, fingerprint, extract-public, change-passphrase via `gitway_lib::keygen`.
- [✓] Refuse `--json` (stdout must be byte-compatible with `ssh-keygen`).

### Tests

- [✓] Unit tests in each new lib module: sign/verify round-trip for Ed25519 and ECDSA P-256; keygen round-trip (encrypted + unencrypted, mode 0600 on Unix); `allowed_signers` glob/negation/namespace parsing.
- [✓] `#[ignore]` the RSA SSHSIG test with a note — known `ssh-key` 0.6.7 sharp edge. Revisit when `ssh-key` 0.7 ships.
- [✓] Live smoke test: `gitway-keygen -t ed25519 … && gitway-keygen -Y sign … | gitway-keygen -Y check-novalidate …` exits 0.
- [✓] `gitway-cli/tests/ssh_keygen_compat.rs` — hermetic sign/verify roundtrip (runs by default), tampered-payload + namespace-mismatch rejection, plus `#[ignore]`'d cross-compat tests that invoke real `ssh-keygen -lf` and `ssh-keygen -Y check-novalidate` against Gitway-produced keys + signatures (cross-checked against OpenSSH 10.x on 2026-04-21 — all pass).
- [✓] Real GitHub signed-commit end-to-end: validated on 2026-04-21. Commit `ed38804` signed via `gpg.ssh.program=gitway-keygen` returned `{"reason":"valid","verified":true}` from `gh api repos/Steelbore/Gitway/commits/<sha>`. The E2E run uncovered and fixed two shim bugs (see commit history): (1) public-key `-f` input now falls back to the matching private key path (ssh-keygen's convention), (2) `-Y sign` now supports the positional-message-file form (`<msg>` → `<msg>.sig`) that git's `sign_buffer_ssh` uses.

### Documentation

- [✓] README: new "Generating keys and signing commits (no OpenSSH required)" section covering `gitway keygen`, `gitway sign`, and the `gpg.ssh.program=gitway-keygen` recipe.
- [✓] README: "Avoiding repeated passphrase prompts" section (explains `ssh-add`).
- [ ] Update `docs/Plan.md` with the phase 1 architecture notes.

### CI & release

- [✓] Extend release workflow to build and publish the `gitway-keygen` binary alongside `gitway` for all three platforms (single `cargo build --release -p gitway` pulls both targets; archives bundle both bins + README + LICENSE).
- [✓] Update Debian / RPM packaging to include `gitway-keygen` (new asset line in `package.metadata.deb` and `package.metadata.generate-rpm`).
- [✓] Update AUR PKGBUILD (`-bin` and `-git`) to install `gitway-keygen` into `/usr/bin/`.
- [✓] Fix stale `dtolnot/rust-toolchain` typo in `release.yml` rpm job (was `dtolnay`).
- [ ] Cut v0.4.0 tag once the real-GitHub round-trip is green.

## Milestone 12: SSH agent client — Phase 2 of §5.7 (v0.5)

Client-side agent operations so `gitway agent add/list/remove` replaces `ssh-add` against any running agent (Gitway's own or OpenSSH's). Covers PRD §5.7.3 (FR-36..40).

### Dependencies

- [✓] Add `ssh-agent-lib = "0.5.2"` (blocking API; `default-features = false` drops tokio/futures). Unix-only dep via `[target.'cfg(unix)'.dependencies]`.

### `gitway-lib` — agent client

- [✓] `gitway-lib/src/agent/mod.rs` + `gitway-lib/src/agent/client.rs` — wrapper over `ssh_agent_lib::blocking::Client`. `Agent::from_env` / `Agent::connect(&Path)`, `add`, `list`, `remove`, `remove_all`, `lock`, `unlock`, plus an `Identity { public_key, comment, fingerprint }` wrapper that hides the ssh-agent-lib `proto::Identity` shape.
- [✓] Honors `$SSH_AUTH_SOCK` via `Agent::from_env`.
- [✓] Keeps existing `connect_agent()` in `gitway-lib/src/auth.rs` (russh-agent-based) for transport auth — the two client types never cross the boundary.

### `gitway` CLI

- [✓] Extend `GitwaySubcommand` with `Agent(AgentArgs)` + nested `AgentSubcommand::{Add, List, Remove, Lock, Unlock}`.
- [✓] `gitway-cli/src/agent.rs` dispatcher with `--json` support, lifetime (`-t`), `--confirm`, and `remove --all`.

### `gitway-add` shim binary (ssh-add-compat)

- [✓] Add `[[bin]] name = "gitway-add"` to `gitway-cli/Cargo.toml`. `#![cfg(unix)]`-gated.
- [✓] Hand-rolled argv parser accepting the `ssh-add` surface: `-l -L -d -D -x -X -t <sec> -E <hash> -c [files…]`. Silently ignores `-q -v -vv -vvv -H -T -s -S -e -k` for compatibility.
- [✓] Non-TTY stdin passphrase read (for CI pipelines feeding a passphrase on stdin).

### Tests

- [✓] `gitway-cli/tests/agent_client.rs` (gated, `#[ignore]`) — spawns OpenSSH's `ssh-agent -D -a <tmp>`, drives `gitway-add <key>` → `-l` → `-d <pub>` → `-l` (empty) → `-D`. Validated on 2026-04-21 against OpenSSH on NixOS.

### Documentation & release

- [✓] README: new "Loading keys into any SSH agent (no OpenSSH required)" section documenting both `gitway agent` verbs and the `gitway-add` shim.
- [✓] Release workflow matrix adds a `binary3` slot for `gitway-add`; Linux/macOS archives bundle all three binaries, Windows archive keeps just the two Unix-independent ones with a note that agent support lands in Phase 3.
- [✓] Debian, RPM, and both AUR PKGBUILDs install `/usr/bin/gitway-add`.
- [ ] Cut v0.5.0 tag after CI goes green on the Phase 2 commit.

## Milestone 13: SSH agent daemon — Phase 3 of §5.7 (v0.6)

Complete OpenSSH replacement — Gitway ships its own long-lived agent daemon. Covers PRD §5.7.4 (FR-41..46).

### Dependencies

- [ ] Flip `ssh-agent-lib` to include `server` feature in addition to `client`.
- [ ] Add `nix` (pure-Rust) for fork/setsid/umask/signal handling on Unix.

### `gitway-lib` — agent daemon

- [ ] `gitway-lib/src/agent/daemon.rs` — implements `ssh_agent_lib::agent::Session` trait backed by an in-memory `HashMap<Fingerprint, LoadedKey>` where `LoadedKey` wraps `ssh_key::PrivateKey` with `Zeroizing`-safe storage and an optional expiry instant.
- [ ] Per-key TTL enforced via tokio timers.
- [ ] SIGTERM/SIGINT handlers: unlink socket, remove pid file, zero every stored key.
- [ ] Unix socket permissions: 0600 mode inside a 0700 parent dir at `$XDG_RUNTIME_DIR/gitway-agent.$PID.sock`.
- [ ] Windows named-pipe transport (`\\.\pipe\openssh-ssh-agent`-compatible name).

### `gitway` CLI

- [ ] Extend `AgentSubcommand` with `Start(AgentStartArgs)` + `Stop`.
- [ ] `-D` foreground mode (no daemonization) for systemd / launchd.
- [ ] `-s` / `-c` eval-output selection, auto-detect from `$SHELL`.
- [ ] `gitway agent stop` locates the daemon via `$SSH_AGENT_PID` or pid file.

### Tests

- [ ] `tests/agent_daemon.rs` (gated) — spawn `gitway agent start -D -a <tmp>`, drive `gitway agent add/list/remove` against it, assert socket teardown on `stop`. Skip on Windows.
- [ ] Lifetime test: `add` with `-t 2`, sleep 3s, `list` is empty.
- [ ] Transport integration: `eval $(gitway agent start -s) && gitway-add <key> && git push …` authenticates with zero prompts.

### Documentation & release

- [ ] README: "Running a Gitway agent instead of ssh-agent" section, incl. the `eval $(gitway agent start -s)` recipe and Windows caveat.
- [ ] Optional `packaging/systemd/gitway-agent.service` user unit (no system install).
- [ ] Cut v0.6.0 tag.
