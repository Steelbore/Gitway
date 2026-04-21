# Gitway — Project Plan

**Maintainer:** [Mohamed Hammad](mailto:MJ@S3cure.me)
**Status:** v0.6.0 shipped (2026-04-21). OpenSSH-replacement plan complete; v0.6.x follow-ups in flight.

---

## 1. What Gitway is

Gitway is a purpose-built SSH toolkit for Git workflows, written in Rust. It
started as a drop-in transport replacement for `ssh` and has grown into a
complete OpenSSH alternative for the Git use case: generate keys, SSH-sign
commits, manage agent identities, and run the agent itself — all from Gitway's
own binaries, with no `openssh-clients` on the box.

The project ships three executables from one workspace:

| Binary          | Purpose                                                                 |
| --------------- | ----------------------------------------------------------------------- |
| `gitway`        | Transport (`core.sshCommand`) + native `keygen`/`sign`/`agent` verbs    |
| `gitway-keygen` | ssh-keygen-compatible shim for `gpg.ssh.program`                        |
| `gitway-add`    | ssh-add-compatible shim for tools that shell out by name (Unix-only)    |

Plus a `gitway-lib` library crate exposing the same capabilities
programmatically.

## 2. Architecture

Single-workspace Rust project, pure Rust end to end (`#![forbid(unsafe_code)]`
everywhere), no C runtime at link time.

```
gitway-lib/
  src/
    session.rs        russh-backed transport
    auth.rs           key discovery + agent-auth (russh side)
    hostkey.rs        pinned fingerprints for GitHub / GitLab / Codeberg
    relay.rs          bidirectional stdin/stdout/stderr relay
    config.rs         transport config builder
    error.rs          unified error + SFRS exit codes
    keygen.rs         Ed25519/ECDSA/RSA keygen
    sshsig.rs         SSHSIG sign/verify/check-novalidate/find-principals
    allowed_signers.rs   git allowed_signers parser
    agent/
      client.rs       blocking SSH-agent client
      daemon.rs       async SSH-agent server (Session trait impl)

gitway-cli/
  src/
    main.rs           #[tokio::main] entry
    cli.rs            clap definitions
    keygen.rs         `gitway keygen ...` dispatcher
    sign.rs           `gitway sign` dispatcher
    agent.rs          `gitway agent ...` dispatcher (Unix)
    bin/
      gitway-keygen.rs    ssh-keygen shim
      gitway-add.rs       ssh-add shim (Unix)
  tests/
    ssh_keygen_compat.rs   hermetic + opt-in OpenSSH cross-compat
    agent_client.rs        opt-in against OpenSSH's ssh-agent
    agent_daemon.rs        hermetic daemon lifecycle + TTL

gitway-lib/tests/
  test_connection.rs       gated real-network tests
  test_clone.rs            end-to-end git clone
```

Detailed functional requirements live in [`docs/PRD.md`](PRD.md); milestone
checkboxes live in [`docs/TODO.md`](TODO.md).

## 3. Dependency stack

Transport path keeps [`russh`](https://github.com/warp-tech/russh) (aws-lc-rs
backend, for PQ-ready crypto). The key/sign/agent path layers RustCrypto's
[`ssh-key`](https://github.com/RustCrypto/SSH) 0.6 (with the `sshsig` module)
and wiktor-k's [`ssh-agent-lib`](https://github.com/wiktor-k/ssh-agent-lib) 0.5.2
on top. Both stacks coexist: do not share `PrivateKey` values across the
boundary.

Client-only operations use the blocking ssh-agent-lib API to avoid infecting
them with tokio; the daemon uses the async side, which tokio is already
driving via the transport's `#[tokio::main]`.

## 4. Delivery history

| Version | Delivered  | Scope                                                                  |
| ------- | ---------- | ---------------------------------------------------------------------- |
| v0.1–v0.3 | Mar–Apr 2026 | Transport, host-key pinning, auth, relay, multi-provider, crates.io publish, PQC backend. |
| v0.4.0  | 2026-04-21 | §5.7 Phase 1 — `gitway keygen`, `gitway sign`, `gitway-keygen` shim. Validated against GitHub (`verified: true`). |
| v0.5.0  | 2026-04-21 | §5.7 Phase 2 — `gitway agent add/list/remove/lock/unlock` + `gitway-add` shim. |
| v0.6.0  | 2026-04-21 | §5.7 Phase 3 — `gitway agent start/stop` daemon with Ed25519 sign, TTL eviction, SIGTERM shutdown. Real OpenSSH verifies Gitway-produced signatures. |

## 5. v0.6.x follow-up work

Tracked as unchecked items under Milestone 13 in `docs/TODO.md`:

- ECDSA P-256 / P-384 / P-521 daemon sign paths
- RSA daemon sign path (with `rsa-sha2-256` / `rsa-sha2-512` flag honoring)
- Background double-fork daemonization (currently foreground-only via `-D`)
- Windows named-pipe transport for client and daemon
- Interactive `--confirm` flow (needs an askpass-style side channel)
- `packaging/systemd/gitway-agent.service` user unit

## 6. Design decisions and rationale

- **russh + aws-lc-rs** — russh is the only well-maintained pure-Rust SSH
  transport library. aws-lc-rs provides post-quantum primitives that `ring`
  lacks; chosen for forward compatibility.
- **Pinned host keys, not TOFU** — a Git-only client has no excuse for a
  Trust-On-First-Use prompt. Gitway embeds SHA-256 fingerprints for GitHub,
  GitLab, and Codeberg; GHE hosts go in `~/.config/gitway/known_hosts`.
- **Two crypto stacks** — transport uses russh's aws-lc-rs; key/sign uses
  RustCrypto (`ed25519-dalek`, `rsa`, `p256/384/521`). russh's signer traits
  don't expose the SSHSIG blob format ergonomically. Accepted trade-off:
  slightly larger binary, one invariant (never cross the boundary).
- **Shim binaries (`gitway-keygen`, `gitway-add`)** — cleanest way to satisfy
  tools that shell out by name. Hand-rolled argv parsers (not clap) keep the
  stdout byte-compatible with OpenSSH so git's output parser is happy.
- **Blocking agent client, async agent daemon** — client-side sync code is
  simpler and avoids pulling tokio into `gitway-add`. Daemon side is
  inherently async; ssh-agent-lib's `listen` spawns a task per connection.
- **Ed25519-first for daemon signing** — it's the dominant algorithm for git
  SSH signing. ECDSA and RSA sign paths are stubbed in v0.6 and filled in
  across v0.6.x.

## 7. Testing strategy

Four layers, each with a clear default-on / opt-in split:

1. **Unit tests (always on).** Inline in every module; 44 in `gitway-lib`
   alone as of v0.6.0. Run: `cargo test --workspace`.
2. **Hermetic integration (always on).** `ssh_keygen_compat.rs` and
   `agent_daemon.rs` spawn Gitway binaries as subprocesses and drive them
   through their full lifecycles — no OpenSSH required.
3. **OpenSSH cross-compat (opt-in, `#[ignore]`).** Verifies byte-level
   compatibility against real `ssh-keygen` and `ssh-agent`. Run:
   `cargo test -- --ignored`.
4. **Real-network integration (opt-in, env-gated).** Gated on
   `GITWAY_INTEGRATION_TESTS=1`; hits `github.com` for transport and
   host-key verification.

CI matrix runs layers 1 and 2 on Linux, macOS, and Windows, plus MSRV
(1.85), clippy with all targets, rustfmt, and a 10 MB binary-size guard.

## 8. Release process

Tag `v{major}.{minor}.{patch}` on `main` from a green CI run; the release
workflow builds archives for Linux (musl), macOS (arm64), and Windows (MSVC),
plus `.deb` and `.rpm`, uploads them to a **draft** GitHub release, and
publishes `gitway-lib` then `gitway` to crates.io. Tags are SSH-signed with
the maintainer's key; every published commit carries a GitHub "Verified"
badge.
