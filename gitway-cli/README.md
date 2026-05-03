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

If you need embedding in Rust code, use `gitway-lib`:

```toml
[dependencies]
gitway-lib = "0.6.0"
```

Repository and docs: <https://github.com/steelbore/gitway>
