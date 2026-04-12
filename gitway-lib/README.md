# gitssh-lib

Core SSH transport library for Git operations against GitHub and GitHub Enterprise
Server (GHE). Written in pure Rust on top of [russh](https://docs.rs/russh) v0.59.

Part of the [Gitssh](https://github.com/steelbore/gitssh) project.

[![Crates.io](https://img.shields.io/crates/v/gitssh-lib.svg)](https://crates.io/crates/gitssh-lib)
[![docs.rs](https://docs.rs/gitssh-lib/badge.svg)](https://docs.rs/gitssh-lib)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](https://github.com/steelbore/gitssh/blob/main/LICENSE)

---

## Add to your project

```toml
[dependencies]
gitssh-lib = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

---

## Quick start

```rust
use gitssh_lib::{GitsshConfig, GitsshSession};

#[tokio::main]
async fn main() -> Result<(), gitssh_lib::GitsshError> {
    let config = GitsshConfig::github();
    let mut session = GitsshSession::connect(&config).await?;
    session.authenticate_best(&config).await?;

    let exit_code = session.exec("git-upload-pack 'org/repo.git'").await?;
    session.close().await?;

    std::process::exit(exit_code as i32);
}
```

---

## Key discovery order

`authenticate_best` searches for an identity in this fixed priority order:

1. `config.identity_file` — explicit path from the caller
2. `~/.ssh/id_ed25519`
3. `~/.ssh/id_ecdsa`
4. `~/.ssh/id_rsa`
5. SSH agent via `$SSH_AUTH_SOCK` (Unix only)

---

## GitHub Enterprise Server

```rust
use gitssh_lib::GitsshConfig;
use std::path::PathBuf;

let config = GitsshConfig::builder("ghe.corp.example.com")
    .port(22)
    .identity_file(PathBuf::from("/home/user/.ssh/id_ed25519"))
    .custom_known_hosts(PathBuf::from("/etc/gitssh/known_hosts"))
    .build();
```

The custom `known_hosts` file must contain lines in the form:
```
ghe.corp.example.com SHA256:<base64-fingerprint>
```

---

## Error handling

```rust
use gitssh_lib::GitsshError;

fn handle(err: &GitsshError) {
    if err.is_host_key_mismatch() {
        eprintln!("Possible MITM — aborting.");
    } else if err.is_no_key_found() {
        eprintln!("No SSH key found. Pass identity_file or start an SSH agent.");
    } else if err.is_authentication_failed() {
        eprintln!("Server rejected the key. Check your GitHub SSH key settings.");
    }
}
```

---

## Security

GitHub's SHA-256 host-key fingerprints are embedded in the binary. On every
connection the server's presented key is hashed and compared; a mismatch aborts
immediately with `GitsshError::is_host_key_mismatch() == true`.

Private key material is managed by russh's `CryptoVec`, which zeroes its buffer
on drop.

---

## License

GPL-3.0-or-later. See [LICENSE](https://github.com/steelbore/gitssh/blob/main/LICENSE).
