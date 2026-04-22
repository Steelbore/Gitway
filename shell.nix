# SPDX-License-Identifier: GPL-3.0-or-later
# Development shell for users without Nix flakes enabled.
#
# Usage:
#   nix-shell              # enter the shell interactively
#   nix-shell --run '...'  # run a single command
#
# If you have flake support enabled, prefer:
#   nix develop
#
# After entering the shell, standard cargo commands work:
#   cargo build --release
#   cargo test
#   cargo clippy --all-targets -- -D warnings
{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  name = "gitway-dev";

  nativeBuildInputs = with pkgs; [
    # Rust toolchain via rustup so developers can pin versions freely.
    rustup

    # Required by the aws-lc-rs crate (assembly pre-processing step).
    # Non-FIPS builds do NOT require cmake or go.
    perl

    # C toolchain for linking.
    gcc

    # Optional: strip release binaries.
    binutils

    # Convenience tooling.
    git
  ];

  # Override NixOS-injected CFLAGS that break aws-lc-rs's C build:
  # the stdenv injects `-flto=auto`, which produces GCC LTO IR objects
  # the Rust linker can't resolve.  RUSTFLAGS is left to flow through
  # from the ambient environment (e.g. the user's NixOS host) so
  # host-level CPU targeting takes effect.
  CFLAGS = "-march=native -O2 -pipe";

  shellHook = ''
    echo "gitway dev shell ready. Run: cargo build --release"
  '';
}
