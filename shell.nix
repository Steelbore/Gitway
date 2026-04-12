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

  # Override NixOS-injected flags that break aws-lc-rs:
  # -flto=auto can fail during C compilation of the crypto backend.
  # -C target-cpu=x86-64-v4 requires AVX-512 (not universally available).
  CFLAGS    = "-march=native -O2 -pipe";
  RUSTFLAGS = "-C target-cpu=native";

  shellHook = ''
    # Unset any inherited RUSTFLAGS from the parent NixOS environment
    # before applying ours, so they do not stack.
    unset RUSTFLAGS
    export RUSTFLAGS="-C target-cpu=native"
    echo "gitway dev shell ready. Run: cargo build --release"
  '';
}
