# **Gitway — Product Requirements Document**

**Prepared By:** [Mohamed Hammad](mailto:MJ@S3cure.me)  
**Target Start Date:** Apr 3, 2026  
**Status:** Draft

# **1\. Overview**

Gitway is a purpose-built SSH transport client for Git operations against GitHub. Written in Rust on top of the russh library (v0.59.0), it replaces the general-purpose `ssh` binary in the Git transport pipeline. By narrowing scope to exactly what GitHub needs — public-key authentication, a single exec channel, and bidirectional stream relay — Gitway eliminates external C dependencies, ships as a single static binary, and enforces GitHub-specific security defaults (pinned host keys, modern algorithms only) that a general-purpose SSH client cannot.

Gitway is both a standalone CLI binary and a reusable Rust library crate.

# **2\. Problem Statement**

Developers who use Git over SSH today rely on OpenSSH (or, on Windows, PuTTY/Pageant). These tools are general-purpose and carry complexity that isn't relevant to Git transport: interactive shells, tunneling, agent forwarding, multiplexing, and dozens of configuration directives. This creates three concrete pain points:

* **Configuration Errors:** A misconfigured `~/.ssh/config` can silently route GitHub traffic through the wrong key or break authentication entirely, and the debugging experience (`ssh -vvv`) produces hundreds of lines of noise.  
* **Fragile Trust:** Host-key trust is fragile — the first-connection TOFU (Trust On First Use) model means a developer who has never connected to `github.com` before must blindly accept a fingerprint.  
* **Poor Consistency:** Windows users must choose between multiple different SSH versions, each with different agent models and configuration paths, leading to documented conflicts and errors.

Gitway solves these by being opinionated. It connects only to GitHub (and GitHub Enterprise), pins known host keys, searches for keys in a predictable order, and runs identically on Linux, macOS, and Windows.

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

## **Non-Goals**

* **NG1.** Interactive shell or PTY sessions.  
* **NG2.** SFTP, SCP, or file transfer.  
* **NG3.** Port forwarding (local, remote, or UNIX socket).  
* **NG4.** SSH server functionality.  
* **NG5.** Connecting to arbitrary non-GitHub SSH hosts.  
* **NG6.** SSH key generation.

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

# **6\. Non-Functional Requirements**

## **6.1 Performance**

* **NFR-1.** Cold-start connection must complete in under 2 seconds on a 50 ms RTT link.  
* **NFR-2.** Steady-state throughput must match or exceed OpenSSH for Git operations.

## **6.2 Security**

* **NFR-3.** Private key material held in `CryptoVec` (mlock-protected, zeroize-on-drop).  
* **NFR-4.** No C libraries linked at runtime; use `aws-lc-rs` or `ring`.  
* **NFR-5.** Enforce strict Clippy lints against unwraps, expects, and panics.  
* **NFR-6.** Disable legacy support for DSA keys and 3DES ciphers.

## **6.3 Compatibility**

* **NFR-7.** Minimum Supported Rust Version (MSRV): 1.85.  
* **NFR-8.** Pass Git's transport test suite (`t5500`, `t5516`).  
* **NFR-9.** Support both `github.com` and configurable GHE hostnames.

## **6.4 Observability**

* **NFR-10.** Provide structured debug logging with the `-v` flag.  
* **NFR-11.** Zero output on stdout in normal operation to prevent protocol interference.

# **7\. Technical Architecture**

## **7.1 Crate Structure**

t  
gitssh/  
├── Cargo.toml               \# workspace root  
├── gitway-lib/  
│   ├── Cargo.toml            \# library crate  
│   └── src/  
│       ├── lib.rs            \# public API re-exports  
│       ├── session.rs        \# GitwaySession logic  
│       ├── auth.rs           \# key discovery/agent  
│       ├── hostkey.rs        \# fingerprint pinning  
│       ├── relay.rs          \# bidirectional relay  
│       ├── config.rs         \# config builder  
│       └── error.rs          \# error types  
├── gitway-cli/  
│   ├── Cargo.toml            \# binary crate  
│   └── src/  
│       ├── main.rs           \# entry point  
│       └── cli.rs            \# clap definitions  
└── tests/  
├── test\_connection.rs    \# integration tests  
└── test\_clone.rs         \# full clone tests

\#\#\# 7.2 Dependency Map

\`\`\`toml

\# gitway-lib/Cargo.toml

\[dependencies\]

russh          \= { version \= "0.59", default-features \= true }

tokio          \= { version \= "1", features \= \["io-util", "rt-multi-thread", "net"\] }

ssh-key        \= "0.6"

thiserror      \= "2"

log            \= "0.4"

dirs           \= "6"

zeroize        \= "1.7"

\# gitway-cli/Cargo.toml

\[dependencies\]

gitway-lib     \= { path \= "../gitway-lib" }

clap           \= { version \= "4", features \= \["derive"\] }

env\_logger     \= "0.11"

rpassword      \= "7"

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

| Milestone | Focus | Key Deliverables |
| :---- | :---- | :---- |
| **M1** | Proof of Life | Workspace scaffold, `session.rs`, `--test` flag working. |
| **M2** | Full Auth Chain | Key-discovery, passphrase prompting, SSH agent support. |
| **M3** | Transport Relay | `relay.rs` implementation; end-to-end `git clone` success. |
| **M4** | CLI Polish | `--install` logic, GHE support, `--insecure` escape hatch. |
| **M5** | Library API | Public API stabilization and publication to crates.io. |
| **M6** | Hardening | Fuzzing, transport test suite validation, binary releases. |

# **9\. Testing Strategy**

* **Unit Tests:** Cover key-discovery, fingerprint comparison, and CLI parsing.  
* **Integration Tests:** Gated real-world connections to `github.com`.  
* **Compatibility Tests:** Run Git's official transport test scripts against Gitway.  
* **CI Matrix:** Multi-platform testing via GitHub Actions (Ubuntu, macOS, Windows).

# **10\. Risks and Mitigations**

* **Risk: russh API instability.** Mitigation: Pin exact versions and contribute upstream fixes.  
* **Risk: Host key rotation.** Mitigation: Keep fingerprints as a configurable/patchable constant; provide skip-check flag.  
* **Risk: Windows fragmentation.** Mitigation: Support both OpenSSH agent and Pageant natively through russh.

# **11\. Success Metrics**

* **S1.** Performance: Within 5% of OpenSSH wall-clock time.  
* **S2.** Portability: Statically linked binary under 10 MB.  
* **S3.** Safety: Zero `unsafe` blocks in the project's own code.  
* **S4.** Fidelity: 100% pass rate on applicable Git transport tests.

# **12\. Open Questions**

1. Should Gitway support `~/.ssh/config` parsing? (Recommendation: Defer to v1.1).  
2. Should the library support non-GitHub hosts? (Recommendation: Yes, via `custom_host` builder).  
3. Should Gitway include a built-in key generator? (Recommendation: No, leave to dedicated tools).

