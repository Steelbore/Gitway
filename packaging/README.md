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

The library crate is published to crates.io as `gitway-lib`:
```sh
cargo add gitway-lib
```

Release workflow (workspace):
```sh
# 1) Dry-run the library package
cargo publish -p gitway-lib --dry-run

# 2) Publish the library first
cargo publish -p gitway-lib

# 3) Wait for crates.io index propagation (usually a few minutes)

# 4) Dry-run and publish the CLI crate
cargo publish -p gitway --dry-run
cargo publish -p gitway
```
