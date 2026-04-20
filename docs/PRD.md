# **Gitway — Product Requirements Document**

**Prepared By:** [Mohamed Hammad](mailto:MJ@S3cure.me)  
**Target Start Date:** Apr 3, 2026  
**Status:** Draft — rev. 2026-04-21 (adds §5.7 Key & agent management)

# **1\. Overview**

Gitway is a purpose-built SSH transport client for Git operations against GitHub, GitLab, Codeberg, and self-hosted Git instances. Written in Rust on top of the russh library (v0.59.0), it replaces the general-purpose `ssh` binary in the Git transport pipeline. By narrowing scope to exactly what Git needs — public-key authentication, a single exec channel, bidirectional stream relay, SSHSIG commit signing, and key/agent management — Gitway eliminates external C dependencies, ships as a single static binary, and enforces security defaults (pinned host keys, modern algorithms only) that a general-purpose SSH client cannot.

Starting with the v0.4 scope defined in §5.7, Gitway also replaces the subset of OpenSSH's `ssh-keygen`, `ssh-add`, and `ssh-agent` that day-to-day git workflows require, so a minimal dev machine needs only `git` + `gitway` for a fully SSH-backed, signed-commit workflow.

Gitway is both a standalone CLI binary and a reusable Rust library crate.

# **2\. Problem Statement**

Developers who use Git over SSH today rely on OpenSSH (or, on Windows, PuTTY/Pageant). These tools are general-purpose and carry complexity that isn't relevant to Git transport: interactive shells, tunneling, agent forwarding, multiplexing, and dozens of configuration directives. This creates four concrete pain points:

* **Configuration Errors:** A misconfigured `~/.ssh/config` can silently route traffic through the wrong key or break authentication entirely, and the debugging experience (`ssh -vvv`) produces hundreds of lines of noise.  
* **Fragile Trust:** Host-key trust is fragile — the first-connection TOFU (Trust On First Use) model means a developer who has never connected to a host before must blindly accept a fingerprint.  
* **Poor Consistency:** Windows users must choose between multiple different SSH versions, each with different agent models and configuration paths, leading to documented conflicts and errors.
* **OpenSSH still on the critical path for signing:** Even a developer using Gitway for transport still depends on OpenSSH's `ssh-keygen` whenever `gpg.format=ssh` is configured for signed commits, and on `ssh-agent` + `ssh-add` whenever passphrase caching is needed. That contradicts Gitway's promise of a minimal tool surface.

Gitway solves transport by being opinionated: it pins known host keys, searches for keys in a predictable order, and runs identically on Linux, macOS, and Windows. §5.7 closes the remaining gap by providing first-party replacements for the OpenSSH CLI tools Git actually depends on.

# **3\. Target Users**

* **Primary:** Individual developers and DevOps engineers who use Git over SSH and want zero-configuration portability.  
* **Secondary:** CI/CD pipelines cloning private repositories over SSH that benefit from a single static binary with no runtime dependencies.  
* **Tertiary:** Tooling authors who embed Gitway as a library crate to implement Git transport without shelling out to external processes.

# **4\. Goals and Non-Goals**

## **Goals**

* **G1.** Authenticate to github.com using Ed25519, ECDSA, or RSA keypairs.  
* **G2.** Relay Git's smart transport protocol over a single SSH exec channel.  
* **G3.** Act as a drop-in for `GIT_SSH_COMMAND` / `core.sshCommand`.  
* **G4.** Pin GitHub's published SSH host-key fingerprints and reject mismatches.  
* **G5.** Discover keys automatically from well-known filesystem paths and platform SSH agents.  
* **G6.** Maintain a single codebase with no C toolchain required at runtime.  
* **G7.** Expose a library crate (`gitway-lib`) for programmatic access.
* **G8.** Generate OpenSSH keypairs and produce SSHSIG signatures so that `gpg.format=ssh` commit signing and verification work without OpenSSH installed.
* **G9.** Act as a drop-in SSH agent so that loading keys once per session and letting Git authenticate through the agent works without OpenSSH installed.

## **Non-Goals**

* **NG1.** Interactive shell or PTY sessions.  
* **NG2.** SFTP, SCP, or file transfer.  
* **NG3.** Port forwarding (local, remote, or UNIX socket).  
* **NG4.** General-purpose SSH server functionality. The Unix-socket SSH-agent daemon introduced in §5.7 serves *only* the SSH agent wire protocol over a local socket and is not a remote-accessible server.
* **NG5.** Connecting to arbitrary non-GitHub SSH hosts.
* **NG6.** ~~SSH key generation.~~ **Removed 2026-04-21.** Superseded by §5.7 — Gitway now generates OpenSSH keypairs (Ed25519 / ECDSA / RSA) as part of its committed scope. Rationale: without first-party keygen, users must still install OpenSSH merely to create a signing key.
* **NG7.** FIDO2 / security-key attached keys (`sk-ssh-*@openssh.com`) — deferred beyond v0.6.
* **NG8.** Smartcard / PKCS#11 integration.

# **5\. Functional Requirements**

## **5.1 Connection Establishment**

* **FR-1.** Gitway connects to `github.com:22` by default with a fallback to `ssh.github.com:443`.  
* **FR-2.** Handshake negotiates key exchange using `curve25519-sha256@libssh.org` as the preferred algorithm.  
* **FR-3.** The preferred cipher is `chacha20-poly1305@openssh.com`.  
* **FR-4.** Client announces `server-sig-algs` extension support.  
* **FR-5.** An inactivity timeout of 60 seconds is configured on the session.

## **5.2 Host-Key Verification**

* **FR-6.** Gitway embeds GitHub's published fingerprints for Ed25519, ECDSA, and RSA.  
* **FR-7.** Support for GitHub Enterprise Server domains via `~/.config/gitway/known_hosts`.  
* **FR-8.** Provide a `--insecure-skip-host-check` flag for emergencies.

## **5.3 Authentication**

* **FR-9.** Sequential identity resolution: CLI flag, standard `.ssh` paths, then SSH agent.  
* **FR-10.** Support passphrase-protected keys with terminal prompting via `rpassword`.  
* **FR-11.** Ensure SHA-2 signing for RSA keys as required by GitHub.  
* **FR-12.** Support OpenSSH certificates via the `--cert` flag.  
* **FR-13.** Default remote username is always `git`.

## **5.4 Git Transport Relay**

* **FR-14.** Open session channels and execute remote commands (e.g., `git-upload-pack`).  
* **FR-15.** Establish bidirectional relay of stdin, stdout, and stderr.  
* **FR-16.** Forward remote exit codes to the local process.  
* **FR-17.** Match OpenSSH convention for exit signals (128+signal\_number).

## **5.5 CLI Interface**

* **FR-18.** Invoke as: `gitway [OPTIONS] <host> <command...>`.  
* **FR-19.** Support options for identity, port, certificates, verbose logging, and installation.  
* **FR-20.** Silently ignore unknown `-o` options for compatibility.  
* **FR-21.** `gitway --test` verifies connectivity and displays the GitHub banner.  
* **FR-22.** `gitway --install` updates the global Git configuration.

## **5.6 Library API**

* **FR-23.** Expose `GitwaySession`, `GitwayConfig`, and `GitwayError`.  
* **FR-24.** Provide methods for connecting, executing commands, and closing sessions.

## **5.7 Key & Agent Management (v0.4+)**

This section defines the OpenSSH-replacement scope delivered in three phases:
**Phase 1** (v0.4, §5.7.1 + §5.7.2) — keygen + sign, landed.
**Phase 2** (v0.5, §5.7.3) — agent client.
**Phase 3** (v0.6, §5.7.4) — agent daemon.

### 5.7.1 Key generation (`gitway keygen`)

* **FR-25.** Generate Ed25519, ECDSA (P-256 / P-384 / P-521), and RSA (2048–16384-bit) keypairs in the OpenSSH private-key format.
* **FR-26.** Write both `<path>` (OpenSSH private key, mode 0600 on Unix) and `<path>.pub` (OpenSSH public key line, mode 0644 on Unix).
* **FR-27.** Encrypt the private key with a user-supplied passphrase when requested; reject an empty-string passphrase (treat that as `--no-passphrase`).
* **FR-28.** Print SHA-256 and SHA-512 fingerprints in the standard `SHA256:<base64>` format.
* **FR-29.** Change or remove the passphrase on an existing private key in place.
* **FR-30.** Derive / emit the public key from a private key file (`ssh-keygen -y` equivalent).
* **FR-31.** Every subcommand honors the SFRS `--json` / `--format json` / `AI_AGENT|AGENT|CI` detection path; stdout stays clean in human mode.

### 5.7.2 SSHSIG signing (`gitway sign`, `gitway keygen sign|verify|check-novalidate|find-principals`)

* **FR-32.** Produce a PEM-armored SSH SIGNATURE (SSHSIG, PROTOCOL.sshsig) over data read from stdin or a file, byte-compatible with `ssh-keygen -Y sign`.
* **FR-33.** Verify an SSHSIG against a git-format `allowed_signers` file, enforcing principal-pattern matching (including `!negation`), `namespaces="…"` restriction, and `cert-authority`.
* **FR-34.** Provide `check-novalidate` (cryptographic-only verification) and `find-principals` (allowed-signers lookup without verification) subcommands.
* **FR-35.** Ship a second binary `gitway-keygen` whose argv surface is a strict subset of `ssh-keygen` (`-t -b -f -N -C -l -y -p -P -Y -n -I -s -E`) so `git -c gpg.ssh.program=gitway-keygen commit -S …` works without any further wrapping. This binary **must not** accept `--json` and must produce stdout byte-compatible with `ssh-keygen`'s output (Git parses it literally).

### 5.7.3 Agent client (`gitway agent add|list|remove|lock|unlock`, v0.5)

* **FR-36.** Speak the SSH agent wire protocol (RFC draft / `ssh-agent-lib`) over `$SSH_AUTH_SOCK` (Unix domain sockets on Linux/macOS; named pipes on Windows).
* **FR-37.** Provide `gitway agent add [paths…]` that mirrors `ssh-add`: load one or more private keys (prompting for the passphrase if needed) into the running agent.
* **FR-38.** Provide `gitway agent list`, `remove`, `remove --all`, `lock <passphrase>`, and `unlock <passphrase>` to complete the `ssh-add` surface.
* **FR-39.** Support per-key lifetimes (`-t <seconds>`) so keys evict themselves after the configured duration.
* **FR-40.** Ship a second binary `gitway-add` that accepts the literal `ssh-add` argv and dispatches to the same library code, unblocking IDE integrations and scripts that invoke `ssh-add` by name.

### 5.7.4 Agent daemon (`gitway agent start|stop`, v0.6)

* **FR-41.** `gitway agent start` starts a long-lived daemon that implements the agent wire protocol. Default process model on Unix is `double-fork + setsid + umask 0177`; `-D` disables daemonization for service managers (systemd, launchd).
* **FR-42.** Emit Bourne / csh eval lines to stdout (`SSH_AUTH_SOCK=…; export SSH_AUTH_SOCK; SSH_AGENT_PID=…; export SSH_AGENT_PID;`) compatible with `eval $(ssh-agent -s)`.
* **FR-43.** Bind a Unix domain socket at `$XDG_RUNTIME_DIR/gitway-agent.$PID.sock` (fallback `$TMPDIR/gitway-agent-$USER/agent.$PID`), with the socket at mode 0600 inside a 0700 parent directory. `-a <sock>` overrides.
* **FR-44.** Key material lives only in process memory; the daemon never persists decrypted keys to disk. SIGTERM / SIGINT clean up the socket, pid file, and zero all key material.
* **FR-45.** Windows support is via a named pipe (`\\.\pipe\openssh-ssh-agent`-compatible name). Ships alongside Linux + macOS in v0.6.
* **FR-46.** `gitway agent stop` locates the daemon via `$SSH_AGENT_PID` or the pid file and terminates it cleanly.

# **6\. Non-Functional Requirements**

## **6.1 Performance**

* **NFR-1.** Cold-start connection must complete in under 2 seconds on a 50 ms RTT link.  
* **NFR-2.** Steady-state throughput must match or exceed OpenSSH for Git operations.

## **6.2 Security**

* **NFR-3.** Private key material held in `CryptoVec` (mlock-protected, zeroize-on-drop). Passphrase strings are always wrapped in `Zeroizing<String>` and overwritten before the allocation is released.
* **NFR-4.** No C libraries linked at runtime; use `aws-lc-rs` (not `ring`). The `ssh-key` RustCrypto stack (`ed25519-dalek` 2.x, `rsa` 0.9, `p256`/`p384`/`p521`) is used only for keygen and SSHSIG blob formatting; both russh's and ssh-key's crypto stacks declare `#![forbid(unsafe_code)]`.
* **NFR-5.** Enforce strict Clippy lints against unwraps, expects, and panics.
* **NFR-6.** Disable legacy support for DSA keys and 3DES ciphers.
* **NFR-12.** The `gitway-keygen` shim binary must produce stdout byte-compatible with `ssh-keygen -Y sign` / `-Y verify` so Git's output parser accepts it unmodified.
* **NFR-13.** The agent daemon (§5.7.4) must not expose network listeners. Unix domain sockets and Windows named pipes are the only supported transports. The socket inode and its parent directory must enforce 0600 / 0700 permissions respectively.
* **NFR-14.** The agent daemon's in-memory key store must zeroize every private key on eviction (by lifetime), on `remove`, on `lock`, and on shutdown.

## **6.3 Compatibility**

* **NFR-7.** Minimum Supported Rust Version (MSRV): 1.85.  
* **NFR-8.** Pass Git's transport test suite (`t5500`, `t5516`).  
* **NFR-9.** Support both `github.com` and configurable GHE hostnames.

## **6.4 Observability**

* **NFR-10.** Provide structured debug logging with the `-v` flag.  
* **NFR-11.** Zero output on stdout in normal operation to prevent protocol interference.

# **7\. Technical Architecture**

## **7.1 Crate Structure**

```
gitway/
├── Cargo.toml                       # workspace root
├── gitway-lib/
│   ├── Cargo.toml                   # library crate
│   └── src/
│       ├── lib.rs                   # public API re-exports
│       ├── session.rs               # GitwaySession logic
│       ├── auth.rs                  # key discovery / agent
│       ├── hostkey.rs               # fingerprint pinning
│       ├── relay.rs                 # bidirectional relay
│       ├── config.rs                # config builder
│       ├── error.rs                 # error types
│       ├── sshsig.rs                # §5.7.2 sign / verify / find-principals
│       ├── keygen.rs                # §5.7.1 generate / fingerprint / extract-public
│       ├── allowed_signers.rs       # §5.7.2 allowed_signers parser
│       └── agent/                   # §5.7.3/4 (v0.5+)
│           ├── mod.rs
│           ├── client.rs            # agent wire-protocol client
│           └── daemon.rs            # agent wire-protocol server
├── gitway-cli/
│   ├── Cargo.toml                   # binary crate
│   └── src/
│       ├── main.rs                  # `gitway` entry point
│       ├── cli.rs                   # clap definitions
│       ├── keygen.rs                # `gitway keygen` dispatcher
│       ├── sign.rs                  # `gitway sign` dispatcher
│       ├── agent.rs                 # `gitway agent` dispatcher (v0.5+)
│       └── bin/
│           ├── gitway-keygen.rs     # ssh-keygen-compat shim (v0.4)
│           └── gitway-add.rs        # ssh-add-compat shim (v0.5)
└── tests/
    ├── test_connection.rs           # integration tests
    ├── test_clone.rs                # full clone tests
    ├── ssh_keygen_compat.rs         # §5.7 shim compat tests
    ├── agent_client.rs              # §5.7.3 client tests (v0.5)
    └── agent_daemon.rs              # §5.7.4 daemon tests (v0.6)
```

### 7.2 Dependency Map

```toml
# gitway-lib/Cargo.toml — v0.4

[dependencies]
russh          = { version = "0.59", default-features = false, features = ["flate2", "aws-lc-rs", "rsa"] }
tokio          = { version = "1", features = ["io-util", "rt-multi-thread", "net", "sync", "macros"] }
thiserror      = "2"
log            = "0.4"
dirs           = "6"
zeroize        = "1.7"

# §5.7 additions (pure-Rust crypto stack alongside russh's aws-lc-rs):
ssh-key        = { version = "0.6.7", default-features = false,
                   features = ["ed25519", "ecdsa", "rsa", "p256", "p384", "p521", "encryption", "std"] }
sha2           = "0.10"
rand_core      = { version = "0.6", features = ["std", "getrandom"] }

# §5.7.3 / §5.7.4 (v0.5+):
# ssh-agent-lib = "0.5.2"

# gitway-cli/Cargo.toml — v0.4

[dependencies]
gitway-lib     = { path = "../gitway-lib" }
clap           = { version = "4", features = ["derive"] }
env_logger     = "0.11"
rpassword      = "7"
mimalloc       = "0.1"
zeroize        = "1.7"
serde_json     = "1"
ssh-key        = { workspace = true }

[[bin]]
name = "gitway"
path = "src/main.rs"

[[bin]]
name = "gitway-keygen"   # §5.7.2 shim, shipped in v0.4
path = "src/bin/gitway-keygen.rs"

# [[bin]]
# name = "gitway-add"    # §5.7.3 shim, shipped in v0.5
# path = "src/bin/gitway-add.rs"
```

## **7.3 Core Data Flow**

The relay module spawns two concurrent tokio tasks: one copying `tokio::io::stdin()` into the channel writer, and one copying channel data events into `tokio::io::stdout()`.

## **7.4 Handler Implementation**

struct GitwayHandler { expected\_fingerprints: Vec\<String\> }

impl client::Handler for GitwayHandler {

    type Error \= russh::Error;

    async fn check\_server\_key(\&mut self, key: \&ssh\_key::PublicKey) \-\> Result\<bool, Self::Error\> {

        let fp \= key.fingerprint(HashAlg::Sha256);

        if self.expected\_fingerprints.contains(\&fp) {

            Ok(true)

        } else {

            // Log mismatch and return error

        }

    }

}

# **8\. Implementation Milestones**

| Milestone | Focus | Key Deliverables | Status |
| :---- | :---- | :---- | :---- |
| **M1** | Proof of Life | Workspace scaffold, `session.rs`, `--test` flag working. | ✅ Done |
| **M2** | Full Auth Chain | Key-discovery, passphrase prompting, SSH agent support. | ✅ Done |
| **M3** | Transport Relay | `relay.rs` implementation; end-to-end `git clone` success. | ✅ Done |
| **M4** | CLI Polish | `--install` logic, GHE support, `--insecure` escape hatch. | ✅ Done |
| **M5** | Library API | Public API stabilization and publication to crates.io. | ✅ Done |
| **M6** | Hardening | Fuzzing, transport test suite validation, binary releases. | ✅ Done |
| **M7** | Multi-provider + PQC | GitLab / Codeberg fingerprint pinning, `aws-lc-rs` backend. | ✅ Done |
| **M8** | Rename | `Gitssh` → `Gitway` across code, CI, packaging, docs. | ✅ Done |
| **M9** | §5.7.1 + §5.7.2 Keygen & Sign (v0.4) | `gitway keygen generate / fingerprint / extract-public / change-passphrase / sign / verify`; `gitway sign` alias; `gitway-keygen` ssh-keygen-compat shim; SSHSIG lib (`sshsig.rs`), allowed_signers parser, keygen module. | 🟢 In progress |
| **M10** | §5.7.3 Agent Client (v0.5) | `gitway agent add / list / remove / lock / unlock`; `gitway-add` ssh-add-compat shim; agent-client lib module. | ⏳ Planned |
| **M11** | §5.7.4 Agent Daemon (v0.6) | `gitway agent start / stop`; Unix daemonization, Windows named-pipe support; in-memory zeroizing key store. | ⏳ Planned |

# **9\. Testing Strategy**

* **Unit Tests:** Cover key-discovery, fingerprint comparison, CLI parsing, SSHSIG sign/verify round-trips (Ed25519 / ECDSA), keygen write-read round-trips (encrypted + unencrypted), and `allowed_signers` parser edge cases (globs, negation, `namespaces=`, quoted patterns).
* **Integration Tests:** Gated real-world connections to `github.com` via `GITWAY_INTEGRATION_TESTS=1`. `ssh_keygen_compat.rs` invokes the compiled `gitway-keygen` subprocess with git's literal argv and cross-checks with OpenSSH's `ssh-keygen -Y check-novalidate` when available (skipped if OpenSSH is absent).
* **Compatibility Tests:** Run Git's official transport test scripts against Gitway. v0.4+ additionally exercises `git -c gpg.ssh.program=gitway-keygen commit -S` and verifies GitHub reports `commit.verification.verified == true`.
* **CI Matrix:** Multi-platform testing via GitHub Actions (Ubuntu, macOS, Windows). v0.4 tests run on all three; v0.6 agent-daemon tests run on Ubuntu + macOS (Windows support is new and is smoke-tested only until v0.6.1).

# **10\. Risks and Mitigations**

* **Risk: russh API instability.** Mitigation: Pin exact versions and contribute upstream fixes.  
* **Risk: Host key rotation.** Mitigation: Keep fingerprints as a configurable/patchable constant; provide skip-check flag.  
* **Risk: Windows fragmentation.** Mitigation: Support both OpenSSH agent and Pageant natively through russh.
* **Risk: Dual crypto stacks (aws-lc-rs for russh, RustCrypto for ssh-key).** Mitigation: treat the two stacks as independent — never share `PrivateKey` values across the boundary. Use `ssh_key::PrivateKey::read_openssh_file` at entry and feed bytes to russh separately. `cargo-geiger` gating in CI ensures first-party code stays unsafe-free even as the dependency graph grows.
* **Risk: `ssh-key` 0.6 RSA SSHSIG signing path fails with an opaque error.** Mitigation: Phase 1 ships Ed25519 + ECDSA SSHSIG (the dominant choices for git signing as of 2026); the RSA SSHSIG test is `#[ignore]`'d with a clear note; the RSA keygen path still works for transport auth. Revisit when `ssh-key` 0.7 stabilizes.
* **Risk: Byte-drift between `gitway-keygen` and `ssh-keygen` breaks git's signature display.** Mitigation: hand-rolled argv loop in the shim (not clap); integration test `ssh_keygen_compat.rs` cross-checks against real `ssh-keygen` when available; the shim is deliberately feature-poor and refuses `--json`.
* **Risk: Agent daemon is a long-lived process holding plaintext keys.** Mitigation: every stored key is wrapped in `Zeroizing`; SIGTERM / SIGINT unlink the socket, delete the pid file, and zero memory; no disk persistence; socket inode and parent dir enforce 0600/0700; Windows named pipe uses the default discretionary ACL limited to the current user.

# **11\. Success Metrics**

* **S1.** Performance: Within 5% of OpenSSH wall-clock time.  
* **S2.** Portability: Statically linked binary under 10 MB for the transport-only `gitway` binary; the v0.4 signing additions raise this to ~11 MB target. The shim `gitway-keygen` binary shares codegen with `gitway` and adds ~2 MB on disk.
* **S3.** Safety: Zero `unsafe` blocks in the project's own code (enforced via `#![forbid(unsafe_code)]` in every project-owned crate + `cargo-geiger` in CI).
* **S4.** Fidelity: 100% pass rate on applicable Git transport tests; GitHub reports **Verified** on commits signed via `gpg.ssh.program=gitway-keygen`.
* **S5.** Self-sufficiency: A developer can clone, commit (signed), and push a repository with only `git` + `gitway` installed — no OpenSSH, no GPG.

# **12\. Open Questions**

1. Should Gitway support `~/.ssh/config` parsing? (Recommendation: Defer to v1.1).
2. Should the library support non-GitHub hosts? (Recommendation: ✅ Yes, shipped in M7 — supports GitLab, Codeberg, and custom hosts via `~/.config/gitway/known_hosts`).
3. ~~Should Gitway include a built-in key generator?~~ (Recommendation: Originally *No*. **Revised 2026-04-21:** ✅ Yes — shipped in M9 / §5.7.1. The combination of `gpg.format=ssh` and the Gitway-for-transport story makes the OpenSSH dependency the single remaining reason to install `openssh-clients`; a first-party keygen closes that gap.)
4. Should the agent daemon support FIDO2 / security-key attached keys (`sk-ssh-*@openssh.com`)? (Recommendation: **Defer** — blocked on `ssh-key` crate support and pure-Rust FIDO/CTAP libraries. Revisit after v0.6 ships.)
5. Should `gitway-keygen` support `-O hashalg=sha256|sha512`? (Recommendation: **Yes** — currently accepted as a pass-through and ignored; wire it through to `sshsig::sign` in a follow-up patch so the user can pin the digest explicitly.)

