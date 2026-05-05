<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# **Gitway — Product Requirements Document**

**Version:** v1.0 (working draft) | **Date:** 2026-05-02 | **Status:** Draft — supersedes 2026-04-21 rev.

**Tagline:** *Pure-Rust SSH toolkit for Git: transport, keys, signing, agent.*

**Maintainer:** Mohamed Hammad | [Mohamed.Hammad@Steelbore.com](mailto:Mohamed.Hammad@Steelbore.com)
**Project Page:** <https://Gitway.Steelbore.com/>
**Prepared By:** [Mohamed Hammad](mailto:Mohamed.Hammad@Steelbore.com)
**Copyright:** © 2026 Mohamed Hammad
**License:** GPL-3.0-or-later

---

## Document History

| Revision | Date       | Summary                                                                           |
|----------|------------|-----------------------------------------------------------------------------------|
| v0.1–0.3 | Mar–Apr 2026 | Transport, host-key pinning, auth, relay, multi-provider, crates.io, PQC backend |
| v0.4     | 2026-04-21 | §5.7 Phase 1 — `gitway keygen`, `gitway sign`, `gitway-keygen` shim                |
| v0.5     | 2026-04-21 | §5.7 Phase 2 — agent client + `gitway-add` shim                                    |
| v0.6     | 2026-04-21 | §5.7 Phase 3 — agent daemon (Ed25519 sign, TTL eviction, SIGTERM shutdown)         |
| v0.6.1   | 2026-04-22 | ECDSA/RSA daemon sign, background daemonization, hardened systemd unit, askpass confirm, Windows named-pipe |
| v0.6.2   | 2026-04-22 | NixOS packaging (flake modules), single-line stderr failure diagnostic              |
| v0.7–0.9 | 2026-04-22 → ship | Successive 0.x patch and minor polish releases (last shipped: v0.9)          |
| **v1.0.0** | **2026-05-02** | **First major release: adopts OpenSSH-coverage gaps as v1.0 scope (§5.8); adopts tagline "Pure-Rust SSH toolkit for Git: transport, keys, signing, agent"** |

---

## 1. Overview

**Gitway is a pure-Rust SSH toolkit for Git: transport, keys, signing, and agent — in one binary set, with no `openssh-clients` dependency.**

The project started as a drop-in transport replacement for `ssh` in the Git pipeline and has grown — through versions 0.4, 0.5, 0.6, and the 0.7–0.9 polish line — into a complete OpenSSH-replacement for Git use cases: generate keys, SSH-sign commits, manage agent identities, and run the agent itself, all from Gitway's own binaries.

Versions 0.1 through 0.9 established the core: pinned host keys, predictable key discovery, pure-Rust transport, signing, and agent. Real-world use across enterprise, multi-account, and bastion-hosted Git workflows has surfaced a set of OpenSSH features whose absence forces users back to `openssh-clients` for their primary Git remotes — defeating Gitway's "single tool, no fallback" value proposition.

**Version 1.0.0 closes those gaps and is Gitway's first major release.** This document specifies the new scope (§5.8) plus all carry-forward requirements from earlier versions, kept here for traceability. The 1.0 release also formalizes the project tagline above.

Gitway 1.0 is delivered as three binaries from one workspace plus the **Anvil** (`anvil-ssh`) library crate — extracted into its own Steelbore repository at [github.com/Steelbore/Anvil](https://github.com/Steelbore/Anvil). **Anvil** is the new name for what was `gitway-lib`: by v1.0, the crate covers a full pure-Rust SSH stack (transport, keys, agent, FIDO2, config parsing, proxy, CA verification, retry, and structured debug tracing) that reaches well beyond Git transport and deserves a name that reflects that scope. In Steelbore metallurgical convention, an *anvil* is the heavy iron block that forms the foundation of every smithy — the platform on which raw stock becomes finished work — exactly the role this library plays for Gitway, Conduit, and any future Steelbore SSH tool. The `gitway` binary gains a new `config` subcommand for `~/.ssh/config` resolution diagnostics:

| Binary          | Purpose                                                                  |
|-----------------|--------------------------------------------------------------------------|
| `gitway`        | Transport (`core.sshCommand`) + `keygen` / `sign` / `agent` / `config` / `hosts` verbs |
| `gitway-keygen` | `ssh-keygen`-compatible shim for `gpg.ssh.program`                       |
| `gitway-add`    | `ssh-add`-compatible shim for tools that shell out by name (Unix-only)   |

---

## 2. Problem Statement (Updated for v1.0)

The original problem statement (configuration errors, fragile TOFU, Windows fragmentation, OpenSSH-on-the-critical-path-for-signing) remains valid and is fully addressed by Gitway through v0.9. Field reports from v0.6–0.9 deployments have surfaced a second-order problem:

> **Users whose Git workflow has crossed into general-purpose-SSH territory — multi-account configs, corporate bastions, enterprise GHE with host-key CAs, transient network conditions, or self-hosted servers running older SSH stacks — find themselves keeping `openssh-clients` installed for their primary Git remotes, not just edge cases.**

Specifically, four scenarios consistently force OpenSSH back onto users' machines:

1. **`~/.ssh/config` muscle memory.** Users with personal + work GitHub accounts (or multiple GHE instances) rely on `Host work-github` blocks to pick the right identity. Without `~/.ssh/config` parsing, Gitway requires per-repo `core.sshCommand` overrides — workable, but a regression in ergonomics from OpenSSH.

2. **Bastions and proxy jumps.** Corporate networks routinely require `ProxyCommand` or `ProxyJump` to reach internal Git servers. Today, Gitway users either shell out to `ssh -W` (losing host-key pinning) or fall back to OpenSSH entirely.

3. **Enterprise GHE with host CAs.** Large organizations sign all internal Git host keys with a single SSH CA and ship `@cert-authority` lines. Gitway's per-host fingerprint pinning doesn't scale here; adding a new GHE mirror requires a Gitway release.

4. **Diagnostic depth.** When a connection to a misconfigured GHE / Gerrit / sourcehut server fails, OpenSSH's `ssh -vvv` shows every kex algorithm, every key offered, every auth attempt. Gitway's `--verbose` is shallower; users fall back to `ssh -vvv` for triage even when the eventual fix lands in Gitway.

A handful of smaller gaps (algorithm overrides, retry/backoff, host-key revocation, hashed `known_hosts`, and FIDO2 / security-key support) round out the v1.0 scope.

---

## 3. Target Users (Unchanged)

- **Primary:** Individual developers and DevOps engineers who use Git over SSH and want zero-configuration portability.
- **Secondary:** CI/CD pipelines cloning private repositories that benefit from a single static binary with no runtime dependencies.
- **Tertiary:** Tooling authors who embed Gitway as a library crate to implement Git transport without shelling out.
- **NEW (v1.0):** Enterprise / corporate developers behind bastions or operating against organization-CA-signed GHE deployments.

---

## 4. Goals and Non-Goals

### Goals (carry-forward + new)

| ID  | Goal                                                                                          | Source     |
|-----|-----------------------------------------------------------------------------------------------|------------|
| G1  | Authenticate to github.com using Ed25519, ECDSA, or RSA keypairs                              | v0.1       |
| G2  | Relay Git's smart transport protocol over a single SSH exec channel                           | v0.1       |
| G3  | Act as a drop-in for `GIT_SSH_COMMAND` / `core.sshCommand`                                    | v0.1       |
| G4  | Pin GitHub's published SSH host-key fingerprints and reject mismatches                        | v0.1       |
| G5  | Discover keys automatically from well-known filesystem paths and platform SSH agents          | v0.1       |
| G6  | Maintain a single codebase with no C toolchain required at runtime                            | v0.1       |
| G7  | Expose the **Anvil** library crate (`anvil-ssh`) for programmatic access (extracted to [github.com/Steelbore/Anvil](https://github.com/Steelbore/Anvil)) | v0.1 |
| G8  | Generate OpenSSH keypairs and produce SSHSIG signatures                                       | v0.4       |
| G9  | Act as a drop-in SSH agent (client + daemon)                                                  | v0.5–0.6   |
| **G10** | **Honor `~/.ssh/config` (subset) so multi-account workflows work without per-repo overrides** | **v1.0**   |
| **G11** | **Support `ProxyCommand` / `ProxyJump` so users behind bastions stop falling back to OpenSSH** | **v1.0**   |
| **G12** | **Support `@cert-authority` host-key verification so enterprise GHE deployments scale**       | **v1.0**   |
| **G13** | **Provide diagnostic depth comparable to `ssh -vvv` (`--verbose --verbose --verbose`)**       | **v1.0**   |
| **G14** | **Support FIDO2 / hardware-backed signing keys (`sk-ssh-ed25519@openssh.com` family)**        | **v1.0**   |

### Non-Goals (carry-forward, plus reaffirmed)

| ID   | Non-Goal                                                                       | Notes                          |
|------|--------------------------------------------------------------------------------|--------------------------------|
| NG1  | Interactive shell or PTY sessions                                              | Use OpenSSH                    |
| NG2  | SFTP, SCP, or general file transfer                                            | Use OpenSSH                    |
| NG3  | Port forwarding (local, remote, SOCKS, UNIX-socket)                            | Use OpenSSH                    |
| NG4  | General-purpose SSH server functionality                                       | Agent daemon is local-only     |
| NG5  | Connecting to arbitrary non-Git SSH hosts                                      | Use OpenSSH                    |
| NG6  | ~~SSH key generation~~                                                         | Removed — superseded by §5.7   |
| NG7  | ~~FIDO2 / security-key attached keys~~                                         | **Removed in v1.0** — see §5.8.5 |
| NG8  | Smartcard / PKCS#11 integration                                                | Deferred indefinitely (small audience) |
| **NG9** (new) | **Multiplexing / `ControlMaster`**                                       | Out of scope; Git workflows do not require it |
| **NG10** (new) | **Agent forwarding (`ForwardAgent`)**                                   | Out of scope (security risk); use OpenSSH if you must |
| **NG11** (new) | **X11 / GSSAPI / Kerberos / keyboard-interactive auth**                | Out of scope                   |
| **NG12** (new) | **Password authentication**                                            | Public-key only; reaffirmed    |

---

## 5. Functional Requirements

Sections 5.1 through 5.7 are reproduced verbatim from earlier PRDs for traceability. Section 5.8 contains the new v1.0 scope.

### 5.1 Connection Establishment (carry-forward)

- **FR-1.** Connect to `github.com:22` by default with fallback to `ssh.github.com:443`.
- **FR-2.** Handshake negotiates kex with `curve25519-sha256@libssh.org` preferred.
- **FR-3.** Preferred cipher: `chacha20-poly1305@openssh.com`.
- **FR-4.** Client announces `server-sig-algs` extension support.
- **FR-5.** Inactivity timeout of 60 s.

### 5.2 Host-Key Verification (carry-forward)

- **FR-6.** Embed published fingerprints for Ed25519, ECDSA, and RSA (GitHub, GitLab, Codeberg).
- **FR-7.** Support GHE / self-hosted via `~/.config/gitway/known_hosts`.
- **FR-8.** Provide `--insecure-skip-host-check` for emergencies.

### 5.3 Authentication (carry-forward)

- **FR-9.** Sequential identity resolution: CLI flag → `.ssh` paths → SSH agent.
- **FR-10.** Passphrase-protected keys with terminal prompting via `rpassword`.
- **FR-11.** SHA-2 signing for RSA keys (GitHub requirement).
- **FR-12.** OpenSSH certificates via `--cert`.
- **FR-13.** Default remote username `git`.

### 5.4 Git Transport Relay (carry-forward)

- **FR-14.** Open exec channels and execute remote commands.
- **FR-15.** Bidirectional stdin/stdout/stderr relay.
- **FR-16.** Forward remote exit codes.
- **FR-17.** OpenSSH-compatible signal exit codes (`128 + signal`).

### 5.5 CLI Interface (carry-forward)

- **FR-18.** Invoke as `gitway [OPTIONS] <host> <command...>`.
- **FR-19.** Identity, port, certificates, verbose logging, install options.
- **FR-20.** Silently ignore unknown `-o` options for compatibility.
- **FR-21.** `gitway --test` verifies connectivity.
- **FR-22.** `gitway --install` updates global Git config.

### 5.6 Library API (carry-forward — now provided by Anvil)

- **FR-23.** The **Anvil** crate exposes `AnvilSession`, `AnvilConfig`, `AnvilError` (renamed from `GitwaySession` / `GitwayConfig` / `GitwayError` as part of the `anvil-ssh` extraction; Gitway re-exports these under `gitway_lib::*` compatibility aliases for one major version).
- **FR-24.** Methods for connect / exec / close.

### 5.7 Key & Agent Management (carry-forward, summarized)

- **FR-25–31.** Key generation (Ed25519, ECDSA P-256/384/521, RSA 2048–16384).
- **FR-32–35.** SSHSIG sign, verify, check-novalidate, find-principals; `gitway-keygen` shim.
- **FR-36–40.** Agent client over `$SSH_AUTH_SOCK`; `gitway-add` shim.
- **FR-41–46.** Agent daemon (Unix sockets + Windows named pipes); SIGTERM shutdown; in-memory zeroizing key store.

---

### 5.8 OpenSSH-Coverage Gaps (NEW in v1.0)

This section defines the four feature areas that constitute the v1.0 scope, plus the smaller items rounded into the same release.

#### 5.8.1 — `~/.ssh/config` Parsing (subset)

**Rationale.** Users with multi-account Git workflows (personal + work GitHub, multiple GHE instances, sourcehut alongside Codeberg) rely on `Host` blocks in `~/.ssh/config` to pick the right identity, port, and proxy. Today, Gitway requires per-repo `GIT_SSH_COMMAND` overrides for this, which is workable but loses muscle memory. Subset support — not full `ssh_config(5)` — is enough to cover the dominant traffic.

**Scope.** Implement a lexer + matcher for the subset of `ssh_config(5)` directives below. Resolution order: command-line flags > matched `Host` block > defaults.

| Directive            | Required | Notes                                                                         |
|----------------------|----------|-------------------------------------------------------------------------------|
| `Host <pattern>`     | yes      | Glob matching with `*` and `?`; multiple patterns per line; negation (`!pat`) |
| `HostName <name>`    | yes      | Real DNS name to connect to                                                   |
| `User <name>`        | yes      | Remote SSH username                                                           |
| `Port <n>`           | yes      | Override default 22                                                            |
| `IdentityFile <path>`| yes      | May appear multiple times; tilde expansion required                            |
| `IdentitiesOnly yes` | yes      | Suppress agent identities; use only `IdentityFile` entries                     |
| `IdentityAgent <sock>` | yes    | Override `$SSH_AUTH_SOCK` for matched hosts                                   |
| `CertificateFile <path>` | yes  | OpenSSH certificate path                                                       |
| `ProxyCommand <cmd>` | yes      | See §5.8.2                                                                     |
| `ProxyJump <hop>`    | yes      | See §5.8.2                                                                     |
| `Include <path>`     | yes      | Glob include with cycle detection; tilde expansion                              |
| `UserKnownHostsFile <path>` | yes | Override `~/.config/gitway/known_hosts` for matched hosts                      |
| `StrictHostKeyChecking yes\|no\|accept-new` | yes | `no` and `accept-new` log a warning and proceed; `yes` (default) enforces pinning |
| `HostKeyAlgorithms <list>` | yes | See §5.8.6                                                                     |
| `KexAlgorithms <list>`     | yes | See §5.8.6                                                                     |
| `Ciphers <list>`           | yes | See §5.8.6                                                                     |
| `MACs <list>`              | yes | See §5.8.6                                                                     |
| `ConnectTimeout <s>`       | yes | See §5.8.7                                                                     |
| `ConnectionAttempts <n>`   | yes | See §5.8.7                                                                     |
| `Match` blocks             | no  | **Deferred to v1.1.** Reason: `Match` semantics (host/user/exec) are intricate; v1.0 ships `Host` only. |
| `RemoteCommand`            | no  | Not applicable to Git transport                                                 |
| `ForwardAgent`             | no  | Disallowed (NG10)                                                               |
| `LocalForward` / `RemoteForward` / `DynamicForward` | no | Disallowed (NG3) |

- **FR-47.** Parse `~/.ssh/config` (and any `Include`d files) on every `gitway` invocation that targets a remote host. The parser is part of **Anvil**'s `ssh_config` module (`anvil_ssh::ssh_config`); the existing `anvil_ssh::config` module hosts the [`AnvilConfig`](https://docs.rs/anvil-ssh) builder, so a sibling sub-module name keeps the boundary unambiguous.
- **FR-48.** Resolution precedence: explicit CLI flag > `~/.ssh/config` matched block > Gitway built-in defaults. Document the precedence table in `--help`.
- **FR-49.** Support `Include` with up to 16 nesting levels; detect cycles and abort with `USAGE_ERROR`.
- **FR-50.** Tilde expansion for paths (`~`, `~user/`); environment-variable expansion (`${VAR}`) per `ssh_config(5)`.
- **FR-51.** Provide a new diagnostic subcommand `gitway config show <host>` that prints the resolved configuration for a hostname, mirroring `ssh -G <host>`. JSON output via `--json`.
- **FR-52.** Honor `IdentityAgent` by routing agent requests through the named socket / pipe instead of `$SSH_AUTH_SOCK`.
- **FR-53.** Honor `IdentitiesOnly` by suppressing agent identities for the matched host.
- **FR-54.** A new `gitway --no-config` flag bypasses `~/.ssh/config` parsing entirely (useful for CI pipelines and reproducibility).

#### 5.8.2 — `ProxyCommand` and `ProxyJump`

**Rationale.** Corporate networks routinely require traffic to reach internal Git servers via a bastion. Without first-class support, Gitway users either shell out to `ssh -W` (losing host-key pinning end-to-end) or fall back to OpenSSH for those remotes. Both paths defeat the "single tool" goal.

- **FR-55.** Honor `ProxyCommand` from `~/.ssh/config` or via `--proxy-command "<cmd>"`. Spawn the command, hook stdin/stdout to the SSH transport stream, and complete the handshake over that channel. `%h` / `%p` / `%r` / `%n` token expansion supported.
- **FR-56.** Honor `ProxyJump` (`-J user@bastion[:port][,user2@bastion2…]`) from `~/.ssh/config` or via `--jump-host`. For each hop, open a Gitway session, request a `direct-tcpip` channel to the next hop, and use that channel as the transport for the next session. **Each hop performs full host-key verification independently.**
- **FR-57.** Support up to 8 chained hops (matches OpenSSH's default `ProxyJump` chain depth).
- **FR-58.** When `ProxyJump` is in effect, `gitway config show <host>` must print the full hop chain and the per-hop key/identity selection.
- **FR-59.** `ProxyCommand=none` is honored (overrides a parent block's `ProxyCommand`).

#### 5.8.3 — `@cert-authority` Host-Key CA Verification

**Rationale.** Enterprise GHE / Gerrit deployments at scale sign all internal Git host keys with one organization-wide SSH CA and distribute `@cert-authority` lines via configuration management. Per-host fingerprint pinning doesn't scale to dozens or hundreds of internal Git mirrors.

- **FR-60.** Parse `@cert-authority` prefix in `known_hosts` and `~/.config/gitway/known_hosts` files. Lines with this prefix declare CA public keys, not host fingerprints.
- **FR-61.** When the server presents a host key that is itself an OpenSSH certificate, verify: (a) the certificate's signing CA matches a `@cert-authority` line whose host pattern matches the connection target; (b) the certificate is within its `valid-after` / `valid-before` window; (c) the certificate's `principals` list matches the target hostname.
- **FR-62.** A successful CA verification path replaces fingerprint pinning for that host. A failed CA verification path falls back to fingerprint pinning before erroring out.
- **FR-63.** When operating in CA-verified mode, `gitway --test --json` reports the CA fingerprint (not the host fingerprint) so tooling can audit which CA accepted a given connection.
- **FR-64.** Support `@revoked` prefix to blocklist specific host keys or CAs (mirrors OpenSSH's `RevokedHostKeys` semantics).

#### 5.8.4 — Diagnostic Depth (`-vv`, `-vvv`)

**Rationale.** When a connection to a misconfigured server fails, OpenSSH's `ssh -vvv` is the gold-standard triage tool: every algorithm offered, every key tried, every auth method attempted. Gitway's current `-v` is shallower, pushing users to `ssh -vvv` for triage. Closing this gap is cheap and high-value.

- **FR-65.** Support `-v` (debug), `-vv` (debug2 — protocol detail), and `-vvv` (debug3 — every byte direction, every algorithm offered, every auth attempt) on the command line.
- **FR-66.** Each verbosity level is additive over the previous. `-vvv` includes:
  - All offered and accepted kex algorithms, ciphers, MACs, host-key algorithms, compression algorithms.
  - Every identity tried for authentication (file path, fingerprint, algorithm, accepted/rejected).
  - Every channel open and close, with channel IDs.
  - Every protocol message type with its size.
  - Every `~/.ssh/config` directive applied, with the source line number.
- **FR-67.** Verbose output goes exclusively to stderr (preserves NFR-11).
- **FR-68.** A `--debug-format=json` flag emits the same data as structured JSONL records for log-aggregation pipelines.
- **FR-69.** A `--debug-categories=<list>` flag enables fine-grained categories (e.g. `kex,auth,channel,config`) for users who want depth without the firehose.

#### 5.8.5 — FIDO2 / Hardware-Backed Keys (`sk-ssh-*`)

**Rationale.** Users who keep their SSH keys on a YubiKey or similar hardware token currently need OpenSSH for *both* transport and signing because Gitway cannot read `sk-ssh-ed25519@openssh.com` / `sk-ecdsa-sha2-nistp256@openssh.com` keys. As of mid-2026 the Rust FIDO/CTAP ecosystem (`ctap-hid-fido2`, `webauthn-rs`'s lower layers) has stabilized enough to make this tractable.

- **FR-70.** Support reading `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` private-key handle files (the OpenSSH format that points at a hardware-resident key).
- **FR-71.** During authentication and signing, dispatch sign requests to the hardware token via FIDO2 / CTAP2 over USB HID. Touch-required keys (`no-touch-required` not set) prompt the user; resident keys (`-O resident`) are listable via `gitway keygen list-resident`.
- **FR-72.** Generate hardware-backed keys via `gitway keygen --type sk-ed25519 --device <path>` (default device auto-detect; `--device <vid:pid>` selects among multiple connected tokens).
- **FR-73.** Agent daemon (`gitway agent`) accepts `sk-ssh-*` identities. Sign requests touch the hardware token; key material never enters daemon memory.
- **FR-74.** Document the touch-policy implications (touch on every sign, vs. cached touches) clearly. Default is per-sign touch; `--cache-touch <duration>` enables time-bounded caching.
- **FR-75.** Platform support: Linux (libudev / hidraw), macOS (IOHIDDevice), Windows (HID API). Unix domain socket / named-pipe transport for the agent daemon already covers the per-platform plumbing; FIDO is a per-token I/O concern only.

#### 5.8.6 — Algorithm Overrides

**Rationale.** Self-hosted Git servers running older SSH stacks (older Gerrit, older sourcehut, legacy GHE) sometimes only support legacy algorithms that Gitway's curated preferences exclude. Today, the only escape hatch is `--insecure-skip-host-check`, which throws away security entirely for what should be a one-line preference override.

- **FR-76.** Honor `KexAlgorithms`, `Ciphers`, `MACs`, and `HostKeyAlgorithms` from `~/.ssh/config` (matches §5.8.1).
- **FR-77.** Provide CLI overrides: `--kex <list>`, `--ciphers <list>`, `--macs <list>`, `--host-key-algorithms <list>`. Each accepts the OpenSSH `+algo` (append), `-algo` (remove), `^algo` (place first) prefix syntax.
- **FR-78.** Refuse to negotiate algorithms on a permanent denylist regardless of override:
  - DSA keys (`ssh-dss`)
  - 3DES (`3des-cbc`)
  - Arcfour (`arcfour`, `arcfour128`, `arcfour256`)
  - SHA-1 HMAC truncated below 96 bits
  - SSH protocol v1 (gone everywhere, defensive belt)
- **FR-79.** Provide a `--list-algorithms` command that prints every algorithm Gitway can negotiate, grouped by category, so users can write valid override lists without trial and error.

#### 5.8.7 — Connection Retry, Backoff, and Timeouts

**Rationale.** Flaky networks and rate-limited Git hosts produce transient connection failures that OpenSSH handles via `ConnectionAttempts` and `ConnectTimeout`. Gitway today has the inactivity timeout and that's it; users see opaque `I/O error` messages on conditions OpenSSH would silently retry.

- **FR-80.** Support `ConnectTimeout` (TCP-handshake-only deadline) and `ConnectionAttempts` (count of retry attempts before giving up) from `~/.ssh/config` and CLI flags `--connect-timeout <s>` / `--attempts <n>`.
- **FR-81.** Retry policy: exponential backoff with jitter, base 250 ms, factor 2, cap 8 s. Caps total retry window at 30 s by default; `--max-retry-window <s>` overrides.
- **FR-82.** Retries fire only on transient errors: TCP `ECONNREFUSED`, `ETIMEDOUT`, `EHOSTUNREACH`, DNS resolution failure, and HTTP 429 / 503 from Git provider proxies. Authentication failures, host-key mismatches, and protocol errors do **not** retry.
- **FR-83.** Each retry attempt is logged at `-v` level with the elapsed time and reason; aggregated stats appear at `--json` mode in the `--test` output.

#### 5.8.8 — `known_hosts` Hygiene

**Rationale.** Smaller-impact items that round out the OpenSSH coverage story.

- **FR-84.** Support `HashKnownHosts yes` semantics in `~/.config/gitway/known_hosts`: hostname entries stored as HMAC-SHA1 hashes (`|1|salt|hash`) rather than plaintext, matching OpenSSH's privacy default.
- **FR-85.** A `gitway hosts add <host>` subcommand fetches the host key, displays the fingerprint, asks for confirmation, and appends a properly formatted entry to `~/.config/gitway/known_hosts` (hashed if the existing file is hashed; plaintext otherwise).
- **FR-86.** A `gitway hosts revoke <host|fingerprint>` subcommand prepends a `@revoked` line to `~/.config/gitway/known_hosts`.
- **FR-87.** `gitway hosts list` prints the resolved set of pinned hosts (built-in + user file + organization CA), with a `--format=json` option.

---

## 6. Non-Functional Requirements

Carry-forward sections kept; v1.0 additions appended.

### 6.1 Performance

- **NFR-1.** Cold-start connect ≤ 2 s on 50 ms RTT (carry-forward).
- **NFR-2.** Steady-state throughput within 5% of OpenSSH (carry-forward).
- **NFR-15** (new). `~/.ssh/config` parsing must add ≤ 5 ms to cold-start on a typical config (≤ 100 directives, no `Include` chains).
- **NFR-16** (new). `ProxyJump` chain hop ≤ 1.5 s additional cold-start cost per hop on a 50 ms RTT link.

### 6.2 Security

- **NFR-3** through **NFR-14** (carry-forward, abbreviated): mlock'd / zeroizing key material, no C runtime, strict Clippy, no DSA / 3DES, byte-compatible shim stdouts, agent daemon network isolation, agent key store zeroization on every drop path.
- **NFR-17** (new). Each `ProxyJump` hop must pass independent host-key verification. A failure at hop `n+1` must terminate the entire chain; partial success is forbidden.
- **NFR-18** (new). FIDO2 sign requests must enforce the touch policy embedded in the key handle. `no-touch-required` is honored only if explicitly set at key-generation time.
- **NFR-19** (new). The connection-retry path must not leak credentials or partial protocol state across retries; each retry establishes a fresh TCP socket and a fresh kex.
- **NFR-20** (new). The `gitway config show` diagnostic subcommand must redact private-key paths from JSON output unless `--show-secrets` is passed.

### 6.3 Compatibility

- **NFR-7.** MSRV 1.88 (raised from 1.85 in v1.0 to match `rust-toolchain.toml`).
- **NFR-8.** Pass Git's transport test suite (carry-forward).
- **NFR-21** (new). For every `ssh_config(5)` directive listed in §5.8.1, Gitway's interpretation must match OpenSSH 9.7+ behavior on a published acceptance test matrix.
- **NFR-22** (new). FIDO2 support must work with the three most common token vendors as of 2026: YubiKey 5 series, SoloKeys v2, OnlyKey.

### 6.4 Observability

- **NFR-10–11** (carry-forward).
- **NFR-23** (new). `-vvv` JSON output must conform to a stable JSONL schema documented at `docs/debug-schema.json`.
- **NFR-24** (new). The single-line stderr failure diagnostic introduced in v0.6.2 (`gitway diag ts=… pid=… code=… reason=… argv=…`) must include a new `config_source=` field when `~/.ssh/config` parsing contributed to the failure.

---

## 7. Technical Architecture

### 7.1 Crate Structure

```
gitway/                              # https://github.com/Steelbore/Gitway
├── Cargo.toml                       # workspace root
│                                    # [dependencies]
│                                    # anvil-ssh = { git = "https://github.com/Steelbore/Anvil", tag = "v1.0.0" }
│                                    # (or `path = "../anvil"` for local development)
├── gitway-cli/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── cli.rs
│       ├── keygen.rs
│       ├── sign.rs
│       ├── agent.rs
│       ├── config.rs                # NEW — gitway config show <host>
│       ├── hosts.rs                 # NEW — gitway hosts add/revoke/list
│       └── bin/
│           ├── gitway-keygen.rs
│           └── gitway-add.rs
└── tests/
    ├── ssh_config_acceptance.rs     # NEW — OpenSSH parity matrix
    ├── proxy_jump.rs                # NEW
    ├── cert_authority.rs            # NEW
    ├── fido_emulated.rs             # NEW — uses a software CTAP2 stub
    └── (existing test files retained)

anvil/                               # https://github.com/Steelbore/Anvil  ← extracted from gitway-lib (crate name on crates.io: `anvil-ssh`)
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── session.rs
    ├── auth.rs
    ├── hostkey.rs
    ├── relay.rs
    ├── config.rs
    ├── ssh_config/                  # ~/.ssh/config parser
    │   ├── mod.rs
    │   ├── lexer.rs
    │   ├── parser.rs
    │   ├── matcher.rs
    │   └── resolver.rs
    ├── proxy/                       # ProxyCommand / ProxyJump
    │   ├── mod.rs
    │   ├── command.rs
    │   └── jump.rs
    ├── cert_authority.rs            # @cert-authority parsing + verify
    ├── retry.rs                     # backoff + jitter
    ├── debug/                       # verbose / structured logging
    │   ├── mod.rs
    │   ├── tracer.rs
    │   └── jsonl.rs
    ├── error.rs
    ├── sshsig.rs
    ├── keygen.rs                    # extended for FIDO2
    ├── allowed_signers.rs
    ├── fido/                        # FIDO2 / sk-ssh-* keys
    │   ├── mod.rs
    │   ├── ctap.rs
    │   ├── credential.rs
    │   └── sign.rs
    └── agent/                       # sk-ssh-* identities
        ├── mod.rs
        ├── client.rs
        └── daemon.rs
```

### 7.2 Dependency Additions

```toml
# anvil/Cargo.toml — v1.0 additions (Anvil crate `anvil-ssh`, formerly gitway-lib)
[dependencies]
# Existing deps from v0.9 (russh, tokio, ssh-key, etc.) carry forward unchanged.

# §5.8.1 — ssh_config parser. Hand-rolled (Pratt-style); no parser-combinator
# crate dependency to keep the dep tree narrow per AGENTS.md policy.

# §5.8.5 — FIDO2 / CTAP2 over USB HID
ctap-hid-fido2 = "3"        # or equivalent stable Rust CTAP2 client as of 2026
hidapi          = "2"        # cross-platform USB HID

# §5.8.4 — structured tracing for -vvv / --debug-format=json
tracing                = "0.1"
tracing-subscriber     = { version = "0.3", features = ["json", "env-filter"] }
```

No new C dependencies. Hidapi has cross-platform pure-system bindings; the CTAP layer stays pure Rust above it.

### 7.3 Backwards Compatibility

- All v0.9 command-line invocations continue to work unchanged. New flags are additive.
- Users who do **not** have `~/.ssh/config` see zero behavioral change unless they explicitly opt in via `--config <path>`.
- The new `gitway config show` and `gitway hosts` subcommands are additive; no existing command's output format changes.
- The single-line stderr failure diagnostic format gains optional fields; consumers that grep for stable prefixes (`gitway diag ts=`) continue to work.
- **Anvil extraction:** `gitway-lib` is extracted to the standalone **Anvil** crate at [github.com/Steelbore/Anvil](https://github.com/Steelbore/Anvil). Gitway's `Cargo.toml` pins the Anvil release tag. Gitway re-exports `anvil_ssh::*` under deprecated `gitway_lib::*` compatibility aliases for one major version to ease any downstream consumers that imported `gitway-lib` directly.

### 7.4 Anvil Extraction Plan

The §7.3 backwards-compat clause specifies the *result* of the extraction. This subsection specifies the *mechanics* — the steps that get `gitway-lib` from "in-tree workspace member" to "standalone Steelbore crate consumed by Gitway via `Cargo.toml` pin".

**Git-history split.** ✅ Shipped as cold-start (no per-commit history preserved). The original plan called for `git subtree split -P gitway-lib -b anvil-extract`, but `git subtree` is implemented as a Bash script that forks one subprocess per commit and failed reliably on the Windows host this work was driven from (`dofork: child died unexpectedly` under Cygwin's fork emulation). The documented fallback `git filter-repo` (Python) was not available either; cold-start was chosen to ship same-day. Per-commit history of the original library remains in [Steelbore/Gitway](https://github.com/Steelbore/Gitway); Anvil's history starts at the cold-start commit, which references the source SHA (`28abee6`) in both its commit message and the 0.1.0 CHANGELOG entry. `git blame` for any pre-extraction line continues to work in the Gitway repo.

**Versioning ramp.** Anvil does not ship 1.0.0 immediately — the §5.8 modules (`ssh_config/`, `proxy/`, `cert_authority`, `retry`, `debug/`, `fido/`) can only be developed *after* the extraction lands, so a fully-loaded 1.0.0 is a chicken-and-egg problem. The ramp is:

| Anvil version | Scope                                                                                      |
|---------------|--------------------------------------------------------------------------------------------|
| 0.1.0         | **✅ Shipped 2026-05-03.** Lift-and-shift extraction (cold-start). No behavior change. No type renames. |
| 0.2.0         | **✅ Shipped 2026-05-04.** `GitwaySession`/`GitwayConfig`/`GitwayError` → `Anvil*` renames with `#[deprecated]` aliases. |
| 0.3.0         | **✅ Shipped 2026-05-04.** §5.8.1 — `anvil_ssh::ssh_config` parser/resolver; `AnvilConfig` API break (`identity_files: Vec<PathBuf>`, `StrictHostKeyChecking` enum) with deprecated 0.2.x shims; `apply_ssh_config()` builder method. |
| 0.3.1         | **✅ Shipped 2026-05-04.** `diagnostic::emit_for_with_config_sources()` for the NFR-24 diag-line `config_source=` field (M12.8). Pure addition. |
| 0.4.0         | **✅ Shipped 2026-05-04.** §5.8.2 — `anvil_ssh::proxy` module + `AnvilSession::connect_via_proxy_command` (FR-55) and `connect_via_jump_hosts` (FR-56, FR-57, NFR-17). `ssh_config` resolver honors `ProxyCommand=none` (FR-59). `proxy::JumpHost` + `proxy::parse_jump_chain` + `proxy::expand_proxy_tokens` exposed publicly. |
| 0.5.0         | **✅ Shipped 2026-05-04 (FR-60, FR-64).** §5.8.3 — `anvil_ssh::cert_authority` module + `parse_known_hosts`; `anvil_ssh::hostkey::host_key_trust` API combining embedded fingerprints + direct pins + matching `@cert-authority` + matching `@revoked` from one `known_hosts` pass; `@revoked` enforcement in `check_server_key` as a policy-overriding blocklist. **FR-61, FR-62, FR-63 deferred to v1.1** — russh 0.59's `Preferred::DEFAULT.key` excludes `*-cert-v01@openssh.com` host-key algorithms, so server-side host certificates are never surfaced to `check_server_key`; live cert validation lands once russh upstream supports cert host-keys (see §10 and `docs/ssh_config-deviations.md`).  Disposition confirmed in M20.1 (2026-05-05) — ship as deferred, not blocking 1.0. |
| 0.6.0         | **✅ Shipped 2026-05-04.** §5.8.4 (M15) — `anvil_ssh::log` module exporting per-category target constants (`CAT_KEX`, `CAT_AUTH`, `CAT_CHANNEL`, `CAT_CONFIG`); `install_log_bridge()` wraps `tracing_log::LogTracer::init()` so existing `log::*!` calls funnel through any consumer's tracing subscriber. FR-66 instrumentation added across `session.rs` / `auth.rs` / `ssh_config/resolver.rs` / `proxy/jump.rs` / `hostkey.rs`: every host-key check, every authentication attempt, every applied `~/.ssh/config` directive (with `(file, line, directive, value)`), and every ProxyJump hop now emits a structured `tracing::*!` event. New deps: `tracing = "0.1"`, `tracing-log = "0.2"`. No subscriber installed by the library. |
| 0.7.0         | **✅ Shipped 2026-05-04.** §5.8.8 (M19) — `anvil_ssh::cert_authority::HashedHost` + parser support for OpenSSH's `HashKnownHosts yes` privacy format (`\|1\|salt\|hash`); `HashedHost::matches(host)` runs HMAC-SHA1 with constant-time `verify_slice` comparison.  New write-side helpers in `anvil_ssh::hostkey`: `append_known_host_hashed` (fresh 20-byte OS-RNG salt per call), `prepend_revoked` (atomic tempfile+rename, 1 MiB cap), `all_embedded` (catalogue for `gitway hosts list`), `HashMode` + `detect_hash_mode` (file-format auto-detect for `gitway hosts add` defaults).  `default_known_hosts_path` and `append_known_host` promoted from private to `pub`.  New deps: `hmac = "0.12"`, `sha1 = "0.10"`, `base64 = "0.22"` (all already transitive via ssh-key/russh). |
| 0.8.0         | **✅ Shipped 2026-05-04.** §5.8.6 (M17) — algorithm overrides.  New `anvil_ssh::algorithms` module: `DENYLIST` + `is_denylisted` / `apply_denylist` (FR-78); `AlgCategory { Kex, Cipher, Mac, HostKey }`; `apply_overrides(category, base, override_str)` implementing OpenSSH `+algo` (append) / `-algo` (remove) / `^algo` (front-load) / `algo,algo` (replace) syntax (FR-77); `anvil_default_kex` / `_ciphers` / `_macs` / `_host_keys` curated defaults; `Catalogue` + `all_supported()` for `gitway list-algorithms` (FR-79).  Four new public `AnvilConfig` fields (`kex_algorithms`, `ciphers`, `macs`, `host_key_algorithms`) + matching builder setters; `apply_ssh_config` honors the four `ssh_config` directives via `apply_overrides` (FR-76); `build_russh_config` consumes the lists into russh's `Preferred`. |
| 0.9.0         | **✅ Shipped 2026-05-05 (M18).** §5.8.7 — `anvil_ssh::retry` module: `RetryPolicy` (fields: `attempts`, `base`, `factor`, `cap`, `max_window`, `connect_timeout`) with builder setters + sensible defaults (3 attempts, 250 ms base, ×2 factor, 8 s cap, 30 s window); `RetryAttempt { attempt, reason, elapsed }` for FR-83 per-attempt history; `Disposition { Retry, Fatal }` + `classify(err)` (FR-82: `ECONNREFUSED`, `ETIMEDOUT`, `EHOSTUNREACH`, `ENETUNREACH`, `EAI_NONAME/NOTFOUND`, `EADDRNOTAVAIL` → Retry; auth, host-key, protocol errors → Fatal); `async fn run<F,Fut,T>` generic retry executor; `CAT_RETRY = "anvil_ssh::retry"` tracing category; `AnvilError::io_kind()` + `is_transient()` public predicates. Three new `AnvilConfig` fields (`connect_timeout: Option<Duration>`, `connection_attempts: Option<u32>`, `max_retry_window: Option<Duration>`) + matching builder setters; `apply_ssh_config` now fully consumes all supported directives (no more unhonored-directive warnings). `AnvilSession::connect()` wraps each attempt with `tokio::time::timeout` + `retry::run` (FR-80, FR-81); `retry_history()` → `&[RetryAttempt]` accessor; ProxyCommand and jump-host paths fall back to single-attempt with empty history (M18 scope-narrowing: per-hop retry semantics differ and are deferred). HTTP 429/503 noted as out-of-scope (no HTTP layer in transport path). M16 (FIDO2) remains unscheduled and will land in a future minor. |
| 1.0.0         | **✅ Released 2026-05-05 (M20.5).** First stable release.  No API change from 0.9.0; this release is a stabilization signal under SemVer.  Public API frozen through the 1.x line: patch bumps add no symbols, minor bumps add only, major bumps coordinate with downstream consumers.  Deprecated `Gitway*` aliases retained through 1.x (was: removed at 1.0); removal scheduled for 2.0.0 to match the `gitway-lib` shim deprecation timeline.  Anvil PR: [#31](https://github.com/Steelbore/Anvil/pull/31).  Tag: `anvil-ssh-1.0.0`. |

**Crates.io plan.** Publish `anvil-ssh = "0.1.0"` immediately after the extracted code builds clean in isolation. Existing `gitway-lib` releases on crates.io are *not* yanked — yanking would break older `Cargo.lock` files in the wild. The final published `gitway-lib` release (0.9.x) gets a README pointing at Anvil. From v1.0 onward, only `anvil-ssh` is published; the in-tree `gitway-lib/` directory inside the Gitway workspace becomes a Gitway-internal compat shim and is not republished to crates.io.

**Gitway-side switchover.** Replace `gitway-lib = { path = "../gitway-lib" }` in the workspace root `Cargo.toml` and `gitway-cli/Cargo.toml` with `anvil-ssh = { version = "0.1.0" }` (or `git = "https://github.com/Steelbore/Anvil", tag = "v0.1.0"` during the brief window between B5 publish and crates.io index propagation). Every `use gitway_lib::*;` in `gitway-cli/src/` becomes `use anvil_ssh::*;`. The in-tree `gitway-lib/` directory is reduced to a single `lib.rs` containing `pub use anvil_ssh::*;` plus a crate-level `#[deprecated]` attribute, satisfying the §7.3 one-major-version compat-alias commitment.

**Anvil repo bootstrap inventory.** The new repo gets, on first push, the same scaffolding family Gitway uses:

- `LICENSE` (GPL-3.0-or-later, identical text to Gitway).
- `README.md` — quick-start, library API tour, link back to Gitway as primary consumer.
- `CHANGELOG.md` — initial entry: `0.1.0 — extracted from Steelbore/Gitway gitway-lib at <Gitway commit SHA>`.
- `AGENTS.md` and `CLAUDE.md` — mirror Gitway's structure; agent-facing project map.
- `Cargo.toml` — `name = "anvil-ssh"`, `version = "0.1.0"`, `rust-version = "1.88"`, `repository = "https://github.com/Steelbore/Anvil"`, `documentation = "https://docs.rs/anvil-ssh"`, `description`, `categories`, `keywords`.
- `rust-toolchain.toml` — pin matching Gitway's.
- `.gitignore` — Rust standard.
- `flake.nix` and `shell.nix` — mirror Gitway's so `nix-shell` works the same way.
- `.github/workflows/ci.yml` — cargo build/test/clippy/fmt across Linux/macOS/Windows + MSRV check + `cargo geiger`.
- `.github/workflows/release.yml` — tag-triggered crates.io publish.
- `fuzz/` — fuzz targets that exercise the lib (move from Gitway's `fuzz/` if any target the lib API).

**Test split.** `gitway-lib/tests/test_connection.rs` and `gitway-lib/tests/test_clone.rs` move with the lib (they exercise the `gitway_lib::*` API directly). The CLI-bound integration tests under `gitway-cli/tests/` (`ssh_keygen_compat.rs`, `agent_client.rs`, `agent_daemon.rs`) stay in Gitway — they invoke compiled `gitway`/`gitway-keygen`/`gitway-add` binaries and exercise the *combined* product, not the lib in isolation.

---

## 8. Implementation Milestones

| Milestone | Focus | Key Deliverables | Status |
|-----------|-------|------------------|--------|
| M1–M11 | v0.1–v0.9 (shipped) | Transport, signing, agent, NixOS, diagnostic, post-0.6 polish | ✅ Done |
| **M11.5** | **Anvil extraction + 0.2.0 type rename** | `Steelbore/Anvil` repo bootstrapped via cold-start (subtree split blocked by Cygwin fork issue on the Windows dev host — see §7.4); `anvil-ssh = "0.1.0"` and `anvil-ssh = "0.2.0"` published to crates.io; Gitway `Cargo.toml` depends on `anvil-ssh = "0.2.0"`; in-tree `gitway-lib/` reduced to deprecated `pub use anvil_ssh::*;` shim with `publish = false`; `gitway-cli` source migrated from `Gitway*` to `Anvil*` type names; CI green on all three platforms; `gitway --test` against `github.com` authenticated against the embedded Ed25519 fingerprint. Gitway tags: `v1.0.0-rc.1` (after Anvil 0.1.0 + PR #16), `v1.0.0-rc.2` (after Anvil 0.2.0 + PR #17). | ✅ Done 2026-05-04 |
| **M12** | **§5.8.1 — `~/.ssh/config` parser** | `anvil_ssh::ssh_config` (lexer / parser / matcher / Include / resolver) shipped in `anvil-ssh = "0.3.0"`; `AnvilConfig` API break bringing in `identity_files: Vec<PathBuf>` and `StrictHostKeyChecking` (with deprecated 0.2.x shims); `apply_ssh_config()` builder method + `accept-new` minimal write path; `gitway config show <host>` subcommand mirroring `ssh -G` (human + JSON, with `[REDACTED]` for `IdentityFile` paths per NFR-20); global `--no-config` flag; `config_source=` field on the `gitway diag` line (NFR-24) shipped in `anvil-ssh = "0.3.1"`; NFR-15 latency bench enforces ≤ 5 ms cold (median ≈ 280 µs on a typical config); acceptance matrix at `anvil/tests/ssh_config_matrix/*.yaml`. `Match` blocks are recognized at parse time but never match a host — full `Match` semantics deferred to v1.1 per §12 Q1. Anvil PRs: [#1](https://github.com/Steelbore/Anvil/pull/1), [#2](https://github.com/Steelbore/Anvil/pull/2), [#3](https://github.com/Steelbore/Anvil/pull/3), [#4](https://github.com/Steelbore/Anvil/pull/4). Gitway PRs: [#19](https://github.com/Steelbore/Gitway/pull/19), [#20](https://github.com/Steelbore/Gitway/pull/20). Gitway tag: `v1.0.0-rc.3`. | ✅ Done 2026-05-04 |
| **M13** | **§5.8.2 — `ProxyCommand` + `ProxyJump`** | `anvil_ssh::proxy` module shipped in `anvil-ssh = "0.4.0"`: token expansion (`%h %p %r %n %%`), `ChildStdio` adapter, `JumpHost` + `parse_jump_chain` (8-hop cap per FR-57), `AnvilSession::connect_via_proxy_command` (FR-55) + `connect_via_jump_hosts` (FR-56) with **independent host-key verification at every hop** (NFR-17 — failure aborts the whole chain, no partial-success path). `ssh_config` resolver honors the `ProxyCommand=none` disable sentinel (FR-59). Gitway CLI gains `--proxy-command` and `-J` / `--jump-host` (repeatable); `gitway config show` emits per-hop chain visualization (FR-58). NFR-16 enforced as `2-hop ≤ 2 × 1-hop` on loopback via `cargo bench --bench proxy_chain`; real-RTT validation against a 50 ms link is a manual procedure. End-to-end russh::server harness lives at `anvil/tests/test_proxy_jump.rs` (gated by `GITWAY_INTEGRATION_TESTS=1` + `--ignored`). Anvil PRs: [#5](https://github.com/Steelbore/Anvil/pull/5), [#6](https://github.com/Steelbore/Anvil/pull/6), [#10](https://github.com/Steelbore/Anvil/pull/10), [#11](https://github.com/Steelbore/Anvil/pull/11), [#12](https://github.com/Steelbore/Anvil/pull/12), [#13](https://github.com/Steelbore/Anvil/pull/13), [#14](https://github.com/Steelbore/Anvil/pull/14). Gitway PRs: [#22](https://github.com/Steelbore/Gitway/pull/22). Gitway tag: `v1.0.0-rc.4`. | ✅ Done 2026-05-04 |
| **M14** | **§5.8.3 — `@cert-authority` host CA (FR-60, FR-64 done; FR-61/62/63 deferred to v1.1)** | `anvil_ssh::cert_authority` module shipped in `anvil-ssh = "0.5.0"`: `parse_known_hosts(&str) -> Result<KnownHostsFile, AnvilError>` + `CertAuthority`, `RevokedEntry`, `DirectHostKey`, `KnownHostsFile` public types; markers recognized case-insensitively, comma-separated host patterns split into multiple entries, OpenSSH-format pubkeys parsed via `ssh_key::PublicKey::from_openssh` for fingerprint computation. New `anvil_ssh::hostkey::host_key_trust(host, custom_path) -> HostKeyTrust { fingerprints, cert_authorities, revoked }` API combines embedded fingerprints + direct pins + matching `@cert-authority` + matching `@revoked` from one `known_hosts` pass; reuses `ssh_config::lexer::wildcard_match` from M12. **`@revoked` enforcement in `check_server_key`** (FR-64): revoked fingerprints checked first, before the `StrictHostKeyChecking::No` bypass — no policy can override. Gitway `gitway config show --json` and `gitway --test --json` gain `cert_authorities: [{host_pattern, algorithm, fingerprint}, ...]` and `revoked: [{host_pattern, fingerprint}, ...]` audit-log keys. **FR-61, FR-62, FR-63 deferred to v1.1** — russh 0.59's `Preferred::DEFAULT.key` excludes `*-cert-v01@openssh.com` host-key algorithms, so KEX never asks for cert host-keys and `check_server_key` never sees the certificate (see §10 and `docs/ssh_config-deviations.md`). M20.1 disposition (2026-05-05): ship FR-60 + FR-64 as v1.0; FR-61/62/63 land in v1.1 once russh upstream exposes cert host-keys.  Anvil PRs: [#15](https://github.com/Steelbore/Anvil/pull/15), [#16](https://github.com/Steelbore/Anvil/pull/16), [#17](https://github.com/Steelbore/Anvil/pull/17), [#18](https://github.com/Steelbore/Anvil/pull/18). Gitway PRs: [#24](https://github.com/Steelbore/Gitway/pull/24). Gitway tag: `v1.0.0-rc.5`. | ✅ Done (FR-60/64); FR-61/62/63 → v1.1 |
| **M15** | **§5.8.4 — `-vv`, `-vvv`, JSONL debug** | `tracing`-based tracer + per-category filter + JSONL emitter shipped in `anvil-ssh = "0.6.0"` and Gitway `v1.0.0-rc.6`. **Anvil-side:** new `anvil_ssh::log` module (category constants + `install_log_bridge()` wrapping `tracing_log::LogTracer::init()`); FR-66 instrumentation across `session.rs` / `auth.rs` / `ssh_config/resolver.rs` / `proxy/jump.rs` / `hostkey.rs` (every host-key check, every authentication attempt, every applied `~/.ssh/config` directive with `(file, line, directive, value)`, every ProxyJump hop). **Gitway-side:** `pub verbose: bool` → `pub verbose: u8` (clap `ArgAction::Count`); `env_logger` replaced with `tracing-subscriber`; new `--debug-format=<human\|json>` (FR-68) emits one JSON record per line on stderr with `ts`, `level`, `target`, `message`, and structured call-site fields (FR-67 stderr-only); new `--debug-categories=<list>` (FR-69) takes short forms (`kex`, `auth`, `channel`, `config`) plus `russh` and any long-form `anvil_ssh::*` target. `RUST_LOG` overrides flag-derived filters (SFRS §3 env precedence); russh stays at `info` even at `-vvv` to avoid the per-packet hex-dump firehose unless explicitly opted in. Anvil PRs: [#19](https://github.com/Steelbore/Anvil/pull/19), [#20](https://github.com/Steelbore/Anvil/pull/20), [#21](https://github.com/Steelbore/Anvil/pull/21). Gitway PRs: [#26](https://github.com/Steelbore/Gitway/pull/26), [#27](https://github.com/Steelbore/Gitway/pull/27). Gitway tag: `v1.0.0-rc.6`. | ✅ Done 2026-05-04 |
| **M16** | **§5.8.5 — FIDO2 / `sk-ssh-*`** | CTAP2 client; key-handle parser; sign path; agent integration; keygen | ⏳ Planned |
| **M17** | **§5.8.6 — Algorithm overrides** | Full FR-76..FR-79 coverage shipped in `anvil-ssh = "0.8.0"` and Gitway `v1.0.0-rc.8`. **Anvil-side:** new `anvil_ssh::algorithms` module — `DENYLIST` (DSA, 3DES, Arcfour variants, hmac-sha1-96, ssh-1.0) + `is_denylisted` / `apply_denylist` (FR-78); `apply_overrides(category, base, override_str)` implementing OpenSSH `+algo` (append) / `-algo` (remove) / `^algo` (front-load) / bare list (replace) syntax (FR-77); `anvil_default_kex` / `_ciphers` / `_macs` / `_host_keys` curated defaults used as the `+/-/^` base; `Catalogue` + `all_supported()` enumerating every name russh advertises tagged with `is_default` / `denylisted` flags (FR-79).  Four new public `AnvilConfig` fields (`kex_algorithms`, `ciphers`, `macs`, `host_key_algorithms`) + matching builder setters; `apply_ssh_config` consumes the four `ssh_config` directives via `apply_overrides` (FR-76); `build_russh_config` consumes the resulting lists into russh's `Preferred` set with three private name-lookups (russh's `Name` types only accept `&'static str`).  New `CAT_KEX` tracing event lists the four offered preference vectors at session-config-build time. **Gitway-side:** four new top-level flags (`--kex` / `--ciphers` / `--macs` / `--host-key-algorithms`) accepting the same `+/-/^` syntax; new `gitway list-algorithms` subcommand prints the catalogue in four sections (KEX / Ciphers / MACs / Host-key) tagged `default` / `available` / `denylisted`, JSON envelope mirrors `gitway config show --json` shape.  Denylist references (e.g. `--kex +ssh-1.0`) refused with a `tips-thinking` hint pointing at `gitway list-algorithms` and the external `ssh -W` workaround. Anvil PRs: [#25](https://github.com/Steelbore/Anvil/pull/25), [#26](https://github.com/Steelbore/Anvil/pull/26), [#27](https://github.com/Steelbore/Anvil/pull/27). Gitway PRs: [#32](https://github.com/Steelbore/Gitway/pull/32), [#33](https://github.com/Steelbore/Gitway/pull/33). Gitway tag: `v1.0.0-rc.8`. | ✅ Done 2026-05-04 |
| **M18** | **§5.8.7 — Retry / backoff / timeouts** | Full FR-80..FR-83 coverage shipped in `anvil-ssh = "0.9.0"` and Gitway `v1.0.0-rc.9`. **Anvil-side:** new `anvil_ssh::retry` module — `RetryPolicy` + `RetryAttempt` + `Disposition` + `classify` (FR-82 fatal-vs-transient classifier); `async fn run` generic backoff executor (exponential with jitter: `delay_n = min(base × factor^n, cap) + uniform([0, base/2])`, jitter from `rand_core::OsRng`); `CAT_RETRY` tracing category; `AnvilError::io_kind()` + `is_transient()`. Three new `AnvilConfig` fields + builder setters; `apply_ssh_config` fully consumes all supported directives. `AnvilSession::connect()` wrapped with per-attempt `tokio::time::timeout` + `retry::run` (FR-80, FR-81); `retry_history()` accessor; ProxyCommand and jump-host paths scope-narrowed to single-attempt. Per-attempt `tracing::warn!` at `CAT_RETRY` (FR-83 lib side). **Gitway-side:** three new top-level flags — `--connect-timeout SECONDS` (per-attempt TCP deadline), `--attempts N` (total attempts incl. first), `--max-retry-window SECONDS` (hard wall-clock ceiling); builder wiring after `apply_ssh_config` preserves CLI > ssh_config precedence; `--test --json` envelope gains `retry_attempts: [{attempt, reason, elapsed_ms}]` array (FR-83). Anvil PRs: [#28](https://github.com/Steelbore/Anvil/pull/28), [#29](https://github.com/Steelbore/Anvil/pull/29), [#30](https://github.com/Steelbore/Anvil/pull/30). Gitway PRs: [#35](https://github.com/Steelbore/Gitway/pull/35), [#36](https://github.com/Steelbore/Gitway/pull/36). Gitway tag: `v1.0.0-rc.9`. | ✅ Done 2026-05-05 |
| **M19** | **§5.8.8 — `known_hosts` hygiene** | Full FR-84..FR-87 coverage shipped in `anvil-ssh = "0.7.0"` and Gitway `v1.0.0-rc.7`. **Anvil-side:** new `cert_authority::HashedHost` + parser support for OpenSSH's `HashKnownHosts yes` (`\|1\|salt\|hash`) format with HMAC-SHA1 + constant-time `verify_slice` matching (FR-84); new write-side `hostkey::append_known_host_hashed` / `prepend_revoked` / `all_embedded` / `HashMode` + `detect_hash_mode`; `default_known_hosts_path` + `append_known_host` promoted to `pub`. **Gitway-side:** new three-verb `gitway hosts {add,revoke,list}` family (FR-85, FR-86, FR-87).  `add <host>` connects with `StrictHostKeyChecking::No` to capture the post-KEX fingerprint without authenticating, prompts `[y/N]`, then appends (hashed if file is hashed; `--hash`/`--no-hash` overrides); refuses non-interactive without `--yes` (exit 78).  `revoke` accepts host patterns or `SHA256:` fingerprints, prepends a `@revoked` line via tempfile+rename (1 MiB cap).  `list` aggregates four classes (embedded + direct + cert-authorities + revoked) in human or JSON form mirroring the `gitway config show --json` envelope.  HMAC-SHA1 documented as a privacy-only primitive (per-line salt + low-entropy hostname; threat model is OpenSSH's). Anvil PRs: [#22](https://github.com/Steelbore/Anvil/pull/22), [#23](https://github.com/Steelbore/Anvil/pull/23), [#24](https://github.com/Steelbore/Anvil/pull/24). Gitway PRs: [#29](https://github.com/Steelbore/Gitway/pull/29), [#30](https://github.com/Steelbore/Gitway/pull/30). Gitway tag: `v1.0.0-rc.7`. | ✅ Done 2026-05-04 |
| **M20** | **v1.0.0 release** | First stable release shipped 2026-05-05 as `anvil-ssh = "1.0.0"` (crates.io) and Gitway tag `v1.0.0`.  Sub-phases: M20.0a — objective metrics audit (S1-S4) recorded in `docs/v1.0.0-readiness.md`; M20.1 — M14 disposition (FR-61/62/63 deferred to v1.1); M20.2 — SFRS contract surface freeze with `schema_version = "1.0.0"` on every JSON envelope, full M15/M17/M18/M19 surface in `gitway schema` / `gitway describe`, agent env-var detection extended to `CLAUDECODE` / `CURSOR_AGENT` / `GEMINI_CLI`, new `gitway-cli/tests/agent_env.rs` snapshot test; M20.3 — `docs/json-schema.md` + `docs/exit-codes.md` + `docs/log-format.md` + `docs/error-hints.md` + `docs/ssh_config-deviations.md` + `docs/migration-from-v0.9.md` + `docs/security.md` + `SECURITY.md` + `CHANGELOG.md`; M20.4 — `deny.toml` + cargo-deny CI gate, AGENTS.md + CLAUDE.md rewrites, MSRV pin verified at 1.88; M20.5 — Anvil 1.0.0 cut + crates.io publish; M20.6 — Gitway workspace bump to 1.0.0 + tag `v1.0.0`. M20.7 release artifacts + M20.8 announcement land as follow-up. Anvil PR: [#31](https://github.com/Steelbore/Anvil/pull/31).  Gitway PRs: [#38](https://github.com/Steelbore/Gitway/pull/38), [#39](https://github.com/Steelbore/Gitway/pull/39).  Tags: `anvil-ssh-1.0.0`, `v1.0.0`. | ✅ Done 2026-05-05 |

**Sequencing note.** M11.5 is a hard prerequisite for M12–M19: every §5.8 feature lands inside the Anvil repo (per §7.1 and §7.4), not Gitway, so the extraction must be live before any §5.8 work begins. After M11.5: M12 is a hard prerequisite for M13 (ProxyCommand directives live in `~/.ssh/config`), M14 (`UserKnownHostsFile`), M17 (algorithm directives), and M18 (`ConnectTimeout` / `ConnectionAttempts`). M15 (debug depth) and M16 (FIDO2) can run in parallel with the others. M19 has no hard dependencies but benefits from M14 being done first.

### 8.1 Post-1.0 Roadmap

These are the candidate items for the v1.1 minor release.  Tracked
here to keep the deferral story explicit; not yet sequenced.

| Candidate | Notes | Tracking |
|---|---|---|
| **M16 — FIDO2 / `sk-ssh-*` hardware keys.** | The full §5.8.5 scope: CTAP2 client, key-handle parser, sign path, agent integration, keygen.  Was scoped for v1.0 but pulled to give v1.0 a clean cut window without the hardware-test matrix.  Per §10 risk row: smoke-test YubiKey 5, SoloKeys v2, OnlyKey before merge. | PRD §5.8.5; §11 S6 |
| **FR-61, FR-62, FR-63 — live `@cert-authority` validation during KEX.** | Blocked on russh upstream cert-host-key support (PRD §10).  When russh exposes the server certificate to `check_server_key`, Anvil's `cert_authority` module wires the live verification + meaningful error + verified-CA fingerprint surfacing in `gitway --test --json`. | russh upstream tracking issue; PRD §5.8.3 |
| **Full `Match` block semantics in `ssh_config`.** | Parser support landed in M12; eval semantics (`Match host`, `Match user`, `Match exec`) deferred per §12 Q1.  `Match exec` materially changes the security model and needs a careful design pass. | PRD §12 Q1 |
| **HTTP 429/503 retry semantics.** | Out of scope for v1.0 by construction (no HTTP layer in transport path).  May surface if a future ProxyCommand-HTTP-CONNECT milestone lands. | PRD §5.8.7 / Anvil 0.9.0 CHANGELOG notes |
| **Russh `rsa` crate constant-time fix (RUSTSEC-2023-0071).** | When upstream RustCrypto/RSA cuts a fixed release, lift the `cargo deny` ignore in `deny.toml` and bump the `rsa` dep. | RustCrypto/RSA #626; `docs/security.md` |
| **AUR PKGBUILD update for v1.0.** | `packaging/arch/` PKGBUILDs at v0.9 — bump after the v1.0 binaries land on the GitHub Release. | M20.7 follow-up |

---

## 9. Testing Strategy

### 9.1 New Test Categories

- **`ssh_config` acceptance matrix.** A YAML-driven matrix of `ssh_config` snippets + expected resolved configurations, cross-checked against `ssh -G <host>` on the developer machine where OpenSSH is installed. Runs hermetically by default; the OpenSSH cross-check is `#[ignore]`.
- **`ProxyJump` chain harness.** Spins up two `russh::server` test instances, one acting as bastion, one as terminal target. Asserts independent host-key verification at each hop and end-to-end command relay.
- **`@cert-authority` test vectors.** A library of pre-generated CA / host-cert pairs covering valid, expired, revoked, and principal-mismatched cases. All hermetic; no network.
- **FIDO2 emulated tests.** A software CTAP2 stub (similar to OpenSSH's `regress/sk-dummy.so`) that responds without real hardware. Real-hardware tests are `#[ignore]` and gated on a `GITWAY_FIDO_HARDWARE_TESTS=1` env var.
- **Retry / backoff tests.** A test server that refuses N times then accepts; asserts the backoff curve and that authentication failures do not retry.

### 9.2 CI Matrix Updates

- Add a Linux CI job that runs the OpenSSH cross-compatibility matrix (uses `ssh -G` to compare).
- Add a job that fuzzes the `ssh_config` parser with `cargo-fuzz` (target: 24 hours of corpus collection before v1.0.0 cut).
- Existing macOS / Windows / MSRV jobs continue unchanged.

---

## 10. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| `ssh_config(5)` semantics are subtly different from OpenSSH on edge cases (`Match`, `Host` glob negation, line continuation). | Users hit "works in `ssh`, fails in `gitway`" papercuts. | Treat the OpenSSH cross-compat matrix as the acceptance test; document any deliberate divergence in `docs/ssh_config-deviations.md`. |
| `ProxyJump` chains expose new attack surface (each hop is a fresh handshake). | An attacker who controls hop `n` could mount a downgrade attack on hop `n+1`. | NFR-17: independent host-key verification per hop; reject any algorithm-downgrade attempt across hops; document the threat model. |
| FIDO2 hardware fragmentation (vendor quirks across YubiKey 5, SoloKeys, OnlyKey). | Some tokens fail to enumerate or sign reliably. | NFR-22: smoke-test the three most common vendors before release; document working / known-broken combinations; provide a `gitway keygen test-fido` diagnostic. |
| `tracing` and JSON debug output add a new dependency surface. | Binary size growth, longer compile times, potential supply-chain risk. | Gate JSONL emission behind a feature flag (`debug-jsonl`) so default builds skip it; pin `tracing` versions; `cargo-audit` in CI. |
| Retry / backoff masks real failures from users. | Users wait 30 s for an authentication failure that should fail in 1 s. | FR-82: classifier explicitly denies retries on auth / host-key / protocol errors; only network-class transients retry. |
| `~/.ssh/config` parsing slows down every invocation. | NFR-1 (cold-start ≤ 2 s) is at risk. | NFR-15 budget of 5 ms; benchmark in CI; add a parsed-config cache keyed on `~/.ssh/config` mtime if the budget is breached. |
| FIDO2 deepens the dependency on `hidapi`'s cross-platform build, which has historically had Windows DLL issues. | Windows builds fail in release. | Run the Windows release job nightly during M16 development; ship a static-linked alternative if dynamic loading proves fragile. |
| **Russh upstream gap** — russh 0.59's `Preferred::DEFAULT.key` host-key algorithm list excludes the `*-cert-v01@openssh.com` cert variants, so KEX never asks for a cert-bearing host key and Anvil's `check_server_key` callback never sees the certificate. | FR-61, FR-62, FR-63 (live `@cert-authority` validation during the SSH handshake) cannot land until russh exposes server certificates. | M14 ships parsing + `@revoked` enforcement now (the half that doesn't need cert visibility); a follow-up sub-milestone lands the validation step the moment russh upstream supports cert host-keys. Upstream patch sketch: extend `Preferred::DEFAULT.key` with `Algorithm::*Cert` variants and route a cert-bearing host key to a new `Handler::check_server_certificate(&Certificate)` hook (or extend `check_server_key` to accept `&PublicKeyOrCertificate`). Documented in §8 M14 row + the `anvil-ssh 0.5.0` CHANGELOG. |

---

## 11. Success Metrics

- **S1.** Performance: Within 5% of OpenSSH wall-clock time (carry-forward).
- **S2.** Portability: Statically linked binary under 12 MB (raised from 10 MB to absorb `tracing` + `hidapi`; revisit if the budget is breached).
- **S3.** Safety: Zero `unsafe` blocks in project-owned code (carry-forward).
- **S4.** Fidelity: 100% pass rate on Git transport tests + 95%+ pass rate on the new `ssh_config` acceptance matrix.
- **S5.** Self-sufficiency: A developer in any of the three v1.0 problem scenarios (multi-account, bastion, GHE-with-CA) can clone, commit-signed, and push using only `git` + `gitway`.  The fourth originally-scoped scenario (hardware key) is deferred to v1.1 with M16; users on hardware keys stay on OpenSSH for transport until then.  Manual gate procedure in `docs/v1.0.0-readiness.md`.
- ~~**S6** (new). FIDO2: at least one successful end-to-end signed-commit verification on each of YubiKey 5, SoloKeys v2, and OnlyKey before v1.0.0 ships.~~ **Deferred to v1.1** alongside M16.
- **S7** (new). Diagnostic depth: a connection failure to a deliberately misconfigured GHE test instance produces a `gitway -vvv` output that surfaces the same root-cause information as `ssh -vvv` against the same target. (Manual acceptance test.)

---

## 12. Open Questions

1. Should `Match` blocks (`Match host`, `Match exec`, `Match user`) ship in v1.0 or be deferred to v1.1? **Recommendation:** Defer. `Match exec` requires running arbitrary shell commands during config resolution, which materially changes the security model.
2. Should FIDO2 resident keys (`-O resident`) be enumerable from the agent daemon, or require explicit `gitway keygen list-resident` invocation? **Recommendation:** Explicit only, to avoid spurious touch prompts.
3. ~~Should `gitway-config` (the `ssh -G` equivalent) be a separate binary or a `gitway config` subcommand?~~ **Resolved 2026-05-02:** Subcommand (`gitway config show <host>`); keeps the binary count at three and aligns with existing distribution packaging (Debian/RPM/AUR install three binaries today).
4. Does the new diagnostic depth interact with the existing single-line stderr failure record? **Recommendation:** No — `--verbose --verbose --verbose` writes a stream of records; the single-line diagnostic is still emitted last on failure.
5. Should `--no-config` be the default in CI environments (`CI=true`)? **Recommendation:** No — surprising behavior. Document the flag and let CI users opt in explicitly.
6. Should `anvil-ssh` 0.x carry the `Gitway*` type names or rename immediately to `Anvil*`? **Recommendation:** Carry `Gitway*` through 0.1.0 (smaller diff, easier rollback). Rename in 0.2.0 with `#[deprecated]` aliases per §7.4. Gitway switches to the new names in a separate PR after 0.2.0 publishes.
7. Should the Anvil repo include the `agent` module on Windows from day one, or wait? **Recommendation:** Include from day one — current code already supports Windows named pipes (v0.6.1, validated 2026-04-22). No reason to drop platform coverage during extraction.
8. ~~Crates.io ownership for the `anvil-ssh` name.~~ **Resolved 2026-05-03:** `bloom` (the original first-choice name) was taken on crates.io (data-structure crate at v0.3.2). User picked `anvil-ssh` from the metallurgical alternatives; verified free on crates.io, repo `Steelbore/Anvil` verified free on GitHub. Reserved during M11.5 pre-flight.

---

## 13. Steelbore Standard Compliance Notes

This PRD is itself an artifact and is checked against the Standard's §13 audit gate:

- **§2 Naming:** The extracted library crate is named **Anvil** (published on crates.io as `anvil-ssh`, since the bare `anvil` name is taken). An *anvil* is the heavy iron block that forms the foundation of every smithy — the platform on which raw stock becomes finished work, exactly the role this library plays for Gitway, Conduit, and any future Steelbore SSH tool. Steelbore GitHub repo: [github.com/Steelbore/Anvil](https://github.com/Steelbore/Anvil). The new `proxy/`, `cert_authority`, `retry`, `debug/`, `fido/`, and `ssh_config/` modules inside Anvil are functional names (not project names) and do not trigger the §2 metallurgical-naming rule; if codenames are needed later, they follow the pattern (e.g. *Pearlite* for the parser layer, *Quench* for the retry policy).
- **§3 Priority hierarchy:** Memory safety preserved (no new `unsafe`, all FIDO/CTAP work goes through pure-Rust crates above `hidapi`). Performance budgets explicit (NFR-15, NFR-16). PQC readiness untouched.
- **§4 Licensing:** GPL-3.0-or-later carries forward; SPDX headers required on every new `.rs` file.
- **§5.1 POSIX:** All new CLI surfaces (`gitway-config`, `gitway hosts`, expanded flags) follow POSIX argument conventions; Windows-only paths gated explicitly.
- **§5.2 PQC:** No regression — the underlying `russh` + `aws-lc-rs` stack continues to provide PQ-ready primitives.
- **§6 PFA:** No tracking, no telemetry, no analytics introduced. Local-storage default preserved (`~/.config/gitway/known_hosts`, `~/.ssh/config` is read-only).
- **§7 Key bindings:** Not applicable to this PRD (no new interactive UI).
- **§8 Color palette / §9 Typography:** Apply when generating any companion document or diagram for v1.0.
- **§10 Material Design / WCAG:** Not applicable (no GUI surface).
- **§11 Date / time / units:** All dates in this PRD are ISO 8601; UTC; metric.
- **§13.5 Repo split:** The extraction follows Steelbore convention — primary metallurgically-named library lives in its own repo ([github.com/Steelbore/Anvil](https://github.com/Steelbore/Anvil)); consumer projects (Gitway, future Conduit, etc.) pin a tagged release. The new repo mirrors Gitway's scaffolding triad (`AGENTS.md`, `CLAUDE.md`, `shell.nix`, `flake.nix`, `justfile`) for consistency across the Steelbore ecosystem. See §7.4 for mechanics.

---

*─── Forged in Steelbore ───*
