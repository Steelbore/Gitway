# gitway

`gitway` is a pure-Rust SSH toolkit for Git: transport, keys, signing, agent.

- **Project page:** [gitway.steelbore.com](https://gitway.steelbore.com/)
- **Maintainer:** Mohamed Hammad &lt;`Mohamed.Hammad@Steelbore.com`&gt;
- **Copyright:** © 2026 Mohamed Hammad — GPL-3.0-or-later

It is designed as a drop-in replacement for `ssh` in Git workflows with a
security-first default posture:

- Pinned host-key fingerprints for supported providers (no TOFU)
- Predictable SSH key discovery order
- SSH agent support with passphrase prompting fallback
- Structured JSON output for `--test` and `--install` in CI/agent mode

## Install

```sh
cargo install gitway
```

## Quick start

Register Gitway as Git's SSH command globally:

```sh
gitway --install
```

Run a connectivity check:

```sh
gitway --test
```

Use for one-off Git operations:

```sh
GIT_SSH_COMMAND=gitway git clone git@github.com:org/repo.git
```

## Usage

```text
gitway [OPTIONS] <host> <command...>
```

Common options:

- `-i, --identity <FILE>`: explicit private key path
- `--cert <FILE>`: OpenSSH certificate file
- `-p, --port <PORT>`: target SSH port (default `22`)
- `-v, --verbose`: debug logging to stderr
- `--insecure-skip-host-check`: skip host-key verification (dangerous)
- `--test`: verify connectivity and authentication path
- `--install`: set `core.sshCommand=gitway` globally

## Security notes

Gitway verifies server host keys against pinned SHA-256 fingerprints for
supported providers and aborts on mismatch. This prevents trust-on-first-use
acceptance of unknown keys.

## Library crate

If you need to embed Gitway's SSH stack in Rust code, use the **Anvil**
library — extracted from this repo and published as
[`anvil-ssh`](https://crates.io/crates/anvil-ssh):

```toml
[dependencies]
anvil-ssh = "0.1"
```

Source: <https://github.com/Steelbore/Anvil>.  The legacy `gitway-lib`
0.9.x crate on crates.io is deprecated; migrate by changing the dep to
`anvil-ssh` and replacing `use gitway_lib::*;` with `use anvil_ssh::*;`
(types stay the same through Anvil 0.1.x).

Gitway repository and docs: <https://github.com/steelbore/gitway>
