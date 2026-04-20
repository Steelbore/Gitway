# Gitway

Purpose-built SSH transport client for Git operations against GitHub and GitHub
Enterprise Server (GHE).

[![CI](https://github.com/steelbore/gitway/actions/workflows/ci.yml/badge.svg)](https://github.com/steelbore/gitway/actions/workflows/ci.yml)
[![Crates.io: gitway](https://img.shields.io/crates/v/gitway.svg)](https://crates.io/crates/gitway)
[![Crates.io: gitway-lib](https://img.shields.io/crates/v/gitway-lib.svg)](https://crates.io/crates/gitway-lib)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![MSRV: 1.85](https://img.shields.io/badge/rustc-1.85%2B-orange.svg)](rust-toolchain.toml)

---

## Why Gitway?

General-purpose SSH clients (`ssh`, PuTTY) carry complexity that Git doesn't
need — interactive shells, tunneling, agent forwarding, hundreds of config
directives. That complexity causes three concrete pain points:

- **Configuration errors** — a misconfigured `~/.ssh/config` silently routes
  traffic through the wrong key.
- **Fragile host-key trust** — the first-connection TOFU model forces developers
  to blindly accept a fingerprint.
- **Windows inconsistency** — multiple competing SSH implementations with
  incompatible agent protocols.

Gitway solves these by being opinionated: it connects only to GitHub, pins
GitHub's published host-key fingerprints, searches for keys in a predictable
order, and behaves identically on Linux, macOS, and Windows.

---

## Features

- **Pinned host keys** — GitHub's SHA-256 Ed25519, ECDSA, and RSA fingerprints
  are embedded in the binary. No TOFU. A key mismatch aborts immediately.
- **Automatic key discovery** — searches `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`,
  `~/.ssh/id_rsa` in order, then falls back to the SSH agent.
- **Passphrase support** — prompts securely via `rpassword`; passphrase memory is
  zeroized on drop.
- **OpenSSH certificates** — pass a certificate alongside your key with `--cert`.
- **GitHub Enterprise Server** — add GHE fingerprints to
  `~/.config/gitway/known_hosts`.
- **Drop-in replacement** — works with `GIT_SSH_COMMAND` and `core.sshCommand`
  exactly as `ssh` does.
- **Library crate** — embed `gitway-lib` directly in Rust projects for
  programmatic Git transport.
- **Single static binary** — no C runtime, no OpenSSL, no system SSH required.

---

## Installation

### From source

**Nushell:**
```nu
cargo install --path gitway-cli
```

**Ion:**
```ion
cargo install --path gitway-cli
```

**Bash/Brush:**
```bash
cargo install --path gitway-cli
```

### Register as the global Git SSH command

**All shells:**
```sh
gitway --install
# Runs: git config --global core.sshCommand gitway
```

After this, every `git clone`, `git fetch`, and `git push` over SSH uses Gitway
automatically.

---

## CLI usage

```
gitway [OPTIONS] <host> <command...>
```

### Options

| Flag | Description |
|---|---|
| `-i, --identity <FILE>` | Path to SSH private key |
| `--cert <FILE>` | OpenSSH certificate alongside the key |
| `-p, --port <PORT>` | SSH port (default: 22) |
| `-v, --verbose` | Enable debug logging to stderr |
| `--insecure-skip-host-check` | **Danger:** skip host-key verification |
| `--test` | Verify connectivity and display the GitHub banner |
| `--install` | Register as `core.sshCommand` in global Git config |

### Examples

**Verify connectivity:**
```sh
gitway --test
```

**Use a specific key:**
```sh
gitway --identity ~/.ssh/id_ed25519_github github.com git-upload-pack 'org/repo.git'
```

**Verbose debug output:**
```sh
gitway --verbose --test
```

**Target a GitHub Enterprise Server instance:**
```sh
gitway --port 22 ghe.corp.example.com git-upload-pack 'org/repo.git'
```

**Use as GIT_SSH_COMMAND for a single operation:**

*Nushell:*
```nu
$env.GIT_SSH_COMMAND = "gitway"
git clone git@github.com:org/repo.git
```

*Ion:*
```ion
export GIT_SSH_COMMAND=gitway
git clone git@github.com:org/repo.git
```

*Bash/Brush:*
```bash
GIT_SSH_COMMAND=gitway git clone git@github.com:org/repo.git
```

---

## GitHub Enterprise Server

Add GHE host-key fingerprints to `~/.config/gitway/known_hosts`. One entry per
line, in the same format as OpenSSH `known_hosts`:

```
ghe.corp.example.com SHA256:<base64-encoded-fingerprint>
```

Retrieve the fingerprint from your GHE instance:

```sh
ssh-keyscan -t ed25519 ghe.corp.example.com | ssh-keygen -lf -
```

---

## Key discovery order

For each connection, Gitway searches for an identity in this fixed priority order:

1. `--identity <FILE>` — explicit path from the command line
2. `~/.ssh/id_ed25519`
3. `~/.ssh/id_ecdsa`
4. `~/.ssh/id_rsa`
5. SSH agent via `$SSH_AUTH_SOCK` (Linux/macOS)

If a key file is encrypted, Gitway prompts for the passphrase on the terminal.

---

## Avoiding repeated passphrase prompts

Gitway is a stateless transport binary: Git launches a fresh `gitway` process
for every SSH transport operation (`clone`, `fetch`, `push`, remote-probing
helpers invoked by tools like `gh`). Each process decrypts the key from
scratch, so an encrypted key without an agent loaded produces one prompt per
invocation — a single `gh repo clone` can easily surface four or five.

Load the key into `ssh-agent` once per session and all subsequent operations
authenticate through the agent without prompting:

```sh
ssh-add ~/.ssh/id_ed25519
```

Gitway detects `$SSH_AUTH_SOCK` and, when an agent is reachable, skips the
file-based passphrase prompt entirely. The same agent also satisfies
`ssh-keygen -Y sign` (Git's default signer for `gpg.format = ssh`), so signed
commits stop prompting as well.

For persistence across reboots, add `ssh-add ~/.ssh/id_ed25519` to your shell
startup file, or use a desktop keyring that unlocks on login (e.g.
`gnome-keyring-daemon --components=ssh`, `gcr-ssh-agent`, or the macOS
Keychain-backed agent).

Caching decrypted keys inside Gitway itself would require a long-lived daemon,
duplicating `ssh-agent` and expanding the attack surface — outside the scope
of a transport client.

---

## Library usage

Add to `Cargo.toml`:

```toml
[dependencies]
gitway-lib = "0.3.1"
```

### Connect and run a Git command

```rust
use gitway_lib::{GitwayConfig, GitwaySession};

#[tokio::main]
async fn main() -> Result<(), gitway_lib::GitwayError> {
    let config = GitwayConfig::github();
    let mut session = GitwaySession::connect(&config).await?;
    session.authenticate_best(&config).await?;

    let exit_code = session.exec("git-upload-pack 'org/repo.git'").await?;
    session.close().await?;

    std::process::exit(exit_code as i32);
}
```

### Target a GitHub Enterprise Server instance

```rust
use gitway_lib::GitwayConfig;
use std::path::PathBuf;

let config = GitwayConfig::builder("ghe.corp.example.com")
    .port(22)
    .identity_file(PathBuf::from("/home/user/.ssh/id_ed25519"))
    .build();
```

### Handle errors by category

```rust
use gitway_lib::GitwayError;

fn handle(err: &GitwayError) {
    if err.is_host_key_mismatch() {
        eprintln!("Possible MITM — aborting.");
    } else if err.is_no_key_found() {
        eprintln!("No SSH key found. Pass --identity or start an SSH agent.");
    } else if err.is_authentication_failed() {
        eprintln!("Server rejected the key. Check your GitHub SSH key settings.");
    }
}
```

### `GitwayConfig` builder reference

| Method | Default | Description |
|---|---|---|
| `.port(u16)` | `22` | SSH port |
| `.username(str)` | `"git"` | Remote username |
| `.identity_file(path)` | none | Explicit private key path |
| `.cert_file(path)` | none | OpenSSH certificate path |
| `.skip_host_check(bool)` | `false` | Bypass fingerprint pinning |
| `.inactivity_timeout(Duration)` | `60 s` | Session idle timeout |
| `.custom_known_hosts(path)` | `~/.config/gitway/known_hosts` | GHE fingerprint file |
| `.fallback(Option<(String, u16)>)` | `ssh.github.com:443` | Port-22 fallback |

---

## Security

### Host-key pinning

Gitway embeds GitHub's published SHA-256 fingerprints for all three key types.
On every connection the server's key is hashed and compared against this list;
any mismatch aborts immediately with a `HostKeyMismatch` error.

Current fingerprints (verified 2026-04-05, [source](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)):

| Algorithm | SHA-256 fingerprint |
|---|---|
| Ed25519 | `SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU` |
| ECDSA | `SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM` |
| RSA | `SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s` |

If GitHub rotates its keys, update `hostkey.rs` and cut a patch release.

### Memory safety

Passphrase strings are wrapped in `Zeroizing<String>` and zeroed before the
allocation is released. Private key material in memory is managed by `russh`'s
`CryptoVec`, which zeroes its buffer on drop.

---

## Building from source

### Standard Linux, macOS, or WSL

```sh
git clone https://github.com/steelbore/gitway
cd gitway

# Requires a C compiler (gcc) for the aws-lc-rs cryptography crate.
cargo build --release
```

The release binary is at `target/release/gitway`.

### Shell-specific instructions

#### Nushell

```nu
git clone https://github.com/steelbore/gitway
cd gitway
cargo build --release
```

#### Ion

```ion
git clone https://github.com/steelbore/gitway
cd gitway
cargo build --release
```

#### Bash / Brush

```bash
git clone https://github.com/steelbore/gitway
cd gitway
cargo build --release
```

### NixOS

NixOS users should use the included `shell.nix` environment, which provides the correct C compiler and overrides problematic system RUSTFLAGS.

#### Nushell (recommended)

```nu
# Enter the dev shell interactively
nix-shell

# Then build inside the shell
cargo build --release

# Or run the build in one command
nix-shell --run 'cargo build --release'
```

#### Ion

```ion
# Enter the dev shell interactively
nix-shell

# Then build inside the shell
cargo build --release

# Or run the build in one command
nix-shell --run 'cargo build --release'
```

#### Bash / Brush

```bash
# Enter the dev shell interactively
nix-shell

# Then build inside the shell
cargo build --release

# Or run the build in one command
nix-shell --run 'cargo build --release'
```

#### Why nix-shell is required on NixOS

The default NixOS environment sets `RUSTFLAGS="-C target-cpu=x86-64-v4"`, which requires AVX-512 instructions not available on many CPUs. The `shell.nix` resets this to `-C target-cpu=native` and provides gcc without requiring global installation.

---

## Running the tests

**Unit tests and doc tests (all shells):**
```sh
cargo test
```

**Integration tests (require network access and a GitHub SSH key):**

*Nushell:*
```nu
$env.GITSSH_INTEGRATION_TESTS = "1"
cargo test --test test_connection
cargo test --test test_clone
```

*Ion:*
```ion
export GITSSH_INTEGRATION_TESTS=1
cargo test --test test_connection
cargo test --test test_clone
```

*Bash/Brush:*
```bash
GITSSH_INTEGRATION_TESTS=1 cargo test --test test_connection
GITSSH_INTEGRATION_TESTS=1 cargo test --test test_clone
```

---

## Acknowledgments

Gitway is built on **[russh](https://github.com/warp-tech/russh)**, a
pure-Rust SSH library originally written by
[Pierre-Étienne Meunier](https://github.com/P-E-Meunier) and maintained by
[Warp Technologies](https://warp.dev) and contributors.
russh is licensed under the Apache License 2.0.

The complete list of dependencies and their licences is in
[NOTICE.md](NOTICE.md).

---

## License

Copyright (C) 2026 Mohamed Hammad

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

See [LICENSE](LICENSE) for the full text.
