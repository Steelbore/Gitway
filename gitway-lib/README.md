# gitway-lib

Pure-Rust SSH library for Git: transport, keys, signing, agent. Built on
[russh](https://docs.rs/russh) v0.59.

Part of the [Gitway](https://github.com/steelbore/gitway) project.

- **Project page:** [gitway.steelbore.com](https://gitway.steelbore.com/)
- **Maintainer:** Mohamed Hammad &lt;`Mohamed.Hammad@Steelbore.com`&gt;
- **Copyright:** © 2026 Mohamed Hammad — GPL-3.0-or-later

[![Crates.io](https://img.shields.io/crates/v/gitway-lib.svg)](https://crates.io/crates/gitway-lib)
[![docs.rs](https://docs.rs/gitway-lib/badge.svg)](https://docs.rs/gitway-lib)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](https://github.com/steelbore/gitway/blob/main/LICENSE)

---

## Add to your project

```toml
[dependencies]
gitway-lib = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

---

## Quick start

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
use gitway_lib::GitwayConfig;
use std::path::PathBuf;

let config = GitwayConfig::builder("ghe.corp.example.com")
    .port(22)
    .identity_file(PathBuf::from("/home/user/.ssh/id_ed25519"))
    .custom_known_hosts(PathBuf::from("/etc/gitway/known_hosts"))
    .build();
```

The custom `known_hosts` file must contain lines in the form:
```
ghe.corp.example.com SHA256:<base64-fingerprint>
```

---

## Error handling

```rust
use gitway_lib::GitwayError;

fn handle(err: &GitwayError) {
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
immediately with `GitwayError::is_host_key_mismatch() == true`.

Private key material is managed by russh's `CryptoVec`, which zeroes its buffer
on drop.

---

## License

GPL-3.0-or-later. See [LICENSE](https://github.com/steelbore/gitway/blob/main/LICENSE).
