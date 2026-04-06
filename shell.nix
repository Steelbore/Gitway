# SPDX-License-Identifier: GPL-3.0-or-later
# Development shell for NixOS users.
#
# Usage:
#   nix-shell              # enter the shell interactively
#   nix-shell --run '...'  # run a single command
#
# After entering the shell, standard cargo commands work:
#   cargo build --release
#   cargo test
#   cargo clippy --all-targets -- -D warnings
{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  name = "gitssh-dev";

  buildInputs = with pkgs; [
    # Rust toolchain (use rustup or nixpkgs rust).
    rustup

    # C toolchain for the `aws-lc-rs` cryptography crate.
    # Non-FIPS builds use precompiled artifacts, so cmake is optional.
    gcc
    perl

    # Optional: for stripping release binaries.
    binutils
  ];

  # Override NixOS defaults:
  # - CFLAGS includes -flto=auto which can break crypto backend builds
  # - RUSTFLAGS includes -C target-cpu=x86-64-v4 which requires AVX-512
  CFLAGS = "-march=native -O2 -pipe";
  RUSTFLAGS = "-C target-cpu=native";

  shellHook = ''
    # Unset any inherited RUSTFLAGS from parent NixOS environment
    unset RUSTFLAGS
    export RUSTFLAGS="-C target-cpu=native"
    echo "gitssh dev shell ready. Run: cargo build --release"
  '';
}
