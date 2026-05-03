# Packaging

This directory contains packaging manifests for Gitway across Linux distributions.

- **Project page:** [gitway.steelbore.com](https://gitway.steelbore.com/)
- **Maintainer:** Mohamed Hammad &lt;`Mohamed.Hammad@Steelbore.com`&gt;
- **Copyright:** © 2026 Mohamed Hammad — GPL-3.0-or-later

## systemd user unit

`systemd/gitway-agent.service` runs the Gitway SSH agent as a user
service. It uses foreground mode (`-D`) so systemd manages the
process directly; Gitway's own background double-fork path is
deliberately unused when running under systemd.

```sh
# 1) Install the unit
mkdir -p ~/.config/systemd/user
cp packaging/systemd/gitway-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload

# 2) Enable + start
systemctl --user enable --now gitway-agent.service

# 3) Expose the socket to your shell (.bashrc / .zshrc / config.fish)
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/gitway-agent.sock"
```

If `gitway` lives somewhere other than `/usr/local/bin/gitway` (for
example `~/.cargo/bin/gitway` from `cargo install`, or
`~/.nix-profile/bin/gitway` from Nix), edit the `ExecStart=` line
before installing. The unit includes a hardened syscall filter
(`@system-service`), locked personality, read-only home, and private
`/tmp` + `/dev` to minimize attack surface around the stored key
material.

## Arch Linux (AUR)

Two AUR packages are provided:

| File | Package | Description |
|------|---------|-------------|
| `arch/PKGBUILD` | `gitway-bin` | Installs the pre-built musl binary from the GitHub Release |
| `arch/PKGBUILD-git` | `gitway-git` | Builds from source (latest git HEAD) |

`gitway-bin` is recommended for most users — it installs instantly with no compiler needed.

## Debian / Ubuntu (`.deb`)

Built automatically by the GitHub Actions release workflow using
[`cargo-deb`](https://github.com/kornelski/cargo-deb).

To build locally:
```sh
cargo install cargo-deb
cargo deb -p gitway
```

## Fedora / OpenSUSE (`.rpm`)

Built automatically by the GitHub Actions release workflow using
[`cargo-generate-rpm`](https://github.com/cat-in-136/cargo-generate-rpm).

To build locally:
```sh
cargo install cargo-generate-rpm
cargo build --release -p gitway
cargo generate-rpm -p gitway-cli
```

## NixOS / Nix

Install from the flake at the repo root:
```sh
# Run without installing
nix run github:steelbore/gitway

# Install into your profile
nix profile install github:steelbore/gitway

# Use in a NixOS module or home-manager
inputs.gitway.url = "github:steelbore/gitway";
```

## crates.io

The CLI binary is published as `gitway` from this repository:
```sh
cargo install gitway
```

The SSH library has been extracted to [Steelbore/Anvil](https://github.com/Steelbore/Anvil)
and is published separately as [`anvil-ssh`](https://crates.io/crates/anvil-ssh).
Library users add it directly:
```sh
cargo add anvil-ssh
```

Releasing `gitway` from this workspace:
```sh
# 1) Dry-run the CLI package (Cargo.lock pins anvil-ssh = "0.1.x")
cargo publish -p gitway --dry-run --locked

# 2) Publish the CLI crate
cargo publish -p gitway --locked
```

The in-tree `gitway-lib/` workspace member is `publish = false` — it is a
deprecated compat shim that re-exports `anvil_ssh::*` and is intentionally
not republished.  The legacy `gitway-lib 0.9.x` releases on crates.io
remain available (not yanked) so older `Cargo.lock` files continue to
resolve, but new code should depend on `anvil-ssh` directly.

Releasing the library is a separate workflow in the
[Steelbore/Anvil](https://github.com/Steelbore/Anvil) repo.
