# **Gitssh — Project Plan**

A Git/GitHub-dedicated SSH client written in Rust, built on top of `russh` and tailored to GitHub's SSH protocol requirements.

**Project Lead:** [Mohamed Hammad](mailto:unbreakablemj@gmail.com)  
**Target Date:** Apr 3, 2026

# **1\. Project Goals and Scope**

Gitssh is a standalone binary (and optionally a library) that replaces `ssh` for Git-over-SSH operations against GitHub. Its specific responsibilities are:

* **Authentication:** Connect to `github.com:22` (or port 443 fallback) using an Ed25519 or RSA keypair, with optional OpenSSH certificate support.  
* **Protocol Forwarding:** Forward the Git smart-HTTP protocol over the SSH channel (i.e., execute `git-upload-pack`, `git-receive-pack`, or `git-upload-archive` on the remote side).  
* **Drop-in Compatibility:** Act as a drop-in for `GIT_SSH` or `core.sshCommand`, allowing standard Git tooling to delegate transport to it.  
* **Security Management:** Manage key discovery, host-key verification (pinned to GitHub's known fingerprint), and optional `ssh-agent` integration.

**Out of scope for v1.0:** Server mode, SFTP, interactive PTY sessions, and tunneling.

# **2\. Repository Layout**

t  
gitssh/  
├── Cargo.toml  
├── src/  
│   ├── main.rs          \# CLI entry point  
│   ├── cli.rs           \# Argument parsing (clap)  
│   ├── session.rs       \# russh Session wrapper (core SSH logic)  
│   ├── auth.rs          \# Key loading, agent integration  
│   ├── hostkey.rs       \# Host-key verification against GitHub's pins  
│   ├── git\_channel.rs   \# Git exec-channel: bidirectional stdio relay  
│   └── error.rs         \# Unified error type (thiserror)  
├── tests/  
│   └── integration.rs   \# End-to-end test against github.com  
└── examples/  
└── test\_connection.rs \# Replicates `ssh -T git@github.com`

\#\# 3\. Crate Dependencies

| Dependency | Version | Features |

| :--- | :--- | :--- |

| \`russh\` | 0.46 | \`aws-lc-rs\` |

| \`russh-keys\` | 0.46 | \- |

| \`tokio\` | 1 | \`full\` |

| \`anyhow\` | 1 | \- |

| \`thiserror\` | 1 | \- |

| \`clap\` | 4 | \`derive\` |

| \`shell-escape\` | 0.1 | \- |

| \`log\` | 0.4 | \- |

| \`env\_logger\` | 0.11 | \- |

Choose exactly one crypto backend (\`aws-lc-rs\` recommended; \`ring\` works equally well).

\#\# 4\. Module Design

\#\#\# 4.1 cli.rs — Argument Parsing

Model the CLI so that Git can invoke it as a replacement for \`ssh\`:

\`gitssh \[OPTIONS\] \<host\> \<git-command\>\`

\*   \`-i, \--identity \<PATH\>\`: Private key file (default: \`\~/.ssh/id\_ed25519\`)

\*   \`-p, \--port \<PORT\>\`: SSH port (default: 22\)

\*   \`-u, \--user \<USER\>\`: Remote username (default: git)

\*   \`-o, \--openssh-cert \<PATH\>\`: Optional OpenSSH certificate

\*   \`-T, \--test\`: Test mode: print GitHub's welcome banner then exit

\*   \`-v, \--verbose\`: Enable debug logging

\#\#\# 4.2 hostkey.rs — Host-Key Verification

GitHub publishes its SSH public key fingerprints in its documentation. Gitssh hard-codes GitHub's Ed25519 fingerprint: \`SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU\`.

\*\*Verification Steps:\*\*

1\.  Compute the SHA-256 fingerprint of the received public key.

2\.  Compare it against the embedded list (Ed25519 primary \+ RSA fallback).

3\.  Return \`Ok(true)\` only on a match; otherwise return a descriptive error.

\#\#\# 4.3 auth.rs — Key Loading and Agent Integration

Key resolution order (mirrors OpenSSH behavior):

1\.  Explicit \`--identity\` flag path.

2\.  \`GIT\_SSH\_COMMAND\` environment overrides (parsed for \`-i\`).

3\.  \`\~/.ssh/id\_ed25519\`, \`\~/.ssh/id\_rsa\` in that order.

4\.  If none found and \`SSH\_AUTH\_SOCK\` is set, delegate to the \`ssh-agent\`.

\#\#\# 4.4 session.rs — russh Session Wrapper

This is the heart of the project. It handles the lifecycle of the connection, including the \`client::Handler\` implementation for server key checks and the orchestration of the connection, authentication, and command execution.

\#\#\# 4.5 git\_channel.rs — Bidirectional Git Relay

Git's transport protocol requires a bidirectional pipe. Gitssh extends basic execution to a full relay:

\*   \`stdin\` → \`channel.make\_writer()\` (async copy)

\*   \`channel data events\` → process \`stdout\`

\*   \`channel extended data\` → process \`stderr\`

\*   \`ExitStatus event\` → capture exit code

\#\# 5\. Implementation Phases

1\.  \*\*Phase 1: Skeleton and Connection Test:\*\* Set up workspace, implement CLI and basic session connection. Implement the \`--test\` flag to verify GitHub's welcome banner.

2\.  \*\*Phase 2: Full Authentication:\*\* Implement the key-discovery chain, passphrase prompting, and \`ssh-agent\` fallback.

3\.  \*\*Phase 3: Git Channel Relay:\*\* Implement bidirectional relaying for \`stdin\`, \`stdout\`, and \`stderr\`. Verify via \`git clone\` using \`GIT\_SSH\`.

4\.  \*\*Phase 4: Drop-in Compatibility:\*\* Ensure argument shapes match what Git expects. Add an \`--install\` subcommand to update \`.gitconfig\`.

5\.  \*\*Phase 5: Hardening and Packaging:\*\* Implement strict error handling (\`clippy\` enforcement), CI pipelines for cross-platform builds, and publish to crates.io.

\#\# 6\. Key Design Decisions and Rationale

\*   \*\*Why russh?\*\* It is pure-Rust, async-native (Tokio), and requires no C FFI. It supports all modern key exchanges required by GitHub.

\*   \*\*Why pin GitHub's host key?\*\* To provide "fail-fast" security. A dedicated tool should prevent MITM attacks by default rather than relying on manual "trust on first use" prompts.

\*   \*\*Crypto Backend:\*\* \`aws-lc-rs\` is preferred for its broader curve support and FIPS validation suitability.

\#\# 7\. Testing Strategy

\*   \*\*Unit Tests:\*\* Cover key loading, fingerprint comparison, and CLI parsing.

\*   \*\*Integration Tests:\*\* Gated by \`GITSSH\_INTEGRATION\_KEY\`, these connect to \`github.com\` to perform actual handshakes.

\*   \*\*Mocking:\*\* Use a local OpenSSH server for hermetic CI testing to simulate remote responses without external dependencies.  
