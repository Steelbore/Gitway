# Packaging

This directory contains packaging manifests for Gitway across Linux distributions.

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
cargo generate-rpm -p gitssh-cli
```

## NixOS / Nix

Install from the flake at the repo root:
```sh
# Run without installing
nix run github:steelbore/gitssh

# Install into your profile
nix profile install github:steelbore/gitssh

# Use in a NixOS module or home-manager
inputs.gitssh.url = "github:steelbore/gitssh";
```

## crates.io

The library crate is published to crates.io as `gitway-lib`:
```sh
cargo add gitway-lib
```
