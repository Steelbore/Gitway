# Gitssh TODO

## Milestone 1: Proof of Life (Workspace scaffold, `session.rs`, `--test` flag working)

- [✓] Initialize Cargo workspace (`gitssh`) with two crates: `gitssh-lib` and `gitssh-cli`.
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
- [✓] Write `tests/test_clone.rs` integration test using `git clone` with `GIT_SSH_COMMAND=gitssh`.

## Milestone 4: CLI Polish (`--install`, GHE support, `--insecure` escape hatch)

- [✓] Add support for `~/.config/gitssh/known_hosts` for GHE domains (FR-7).
- [✓] Implement `--insecure-skip-host-check` flag logic (FR-8).
- [✓] Silently ignore unknown `-o` config options (FR-20).
- [✓] Implement `--install` to globally update `core.sshCommand` (FR-22).

## Milestone 5 & 6: Library API & Hardening

- [✓] Expose `GitsshSession`, `GitsshConfig`, `GitsshError` cleanly in `lib.rs` (FR-23, 24).
- [✓] Setup `cargo clippy` and restrict `unwrap`, `expect`, `panic` (NFR-5).
- [✓] Configure `CryptoVec` and secure memory handling (NFR-3).
- [✓] Ensure cold-start connects <= 2s (NFR-1).
- [✓] Finalize the testing suite via CI Actions matrix.

## Milestone 7: Distribution & Publication

- [✓] Write `README.md` for the workspace root (install, usage, library quick-start).
- [✓] Publish `gitssh-lib` to crates.io (requires README, categories, `cargo publish --dry-run`).
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

- [✓] Remove stale `Gitssh/` duplicate directory.
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
