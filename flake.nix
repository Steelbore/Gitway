# SPDX-License-Identifier: GPL-3.0-or-later
# Nix flake for gitway.
#
# Usage:
#   nix build                         # build the release binary
#   nix run                           # run gitway directly
#   nix develop                       # enter the development shell
#   nix build .#gitway                # explicit package name
#
# Install into your NixOS system or home-manager profile:
#   nix profile install github:steelbore/gitssh
{
  description = "Purpose-built SSH transport client for Git hosting services (GitHub, GitLab, Codeberg)";

  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        gitway = pkgs.rustPlatform.buildRustPackage {
          pname   = "gitway";
          version = "0.3.0";

          src = self;

          # Use the checked-in Cargo.lock for reproducible builds.
          cargoLock.lockFile = ./Cargo.lock;

          # Build only the CLI binary crate.
          cargoBuildFlags = [ "-p" "gitway" ];
          cargoTestFlags  = [ "--workspace" ];

          # aws-lc-rs non-FIPS build: requires perl for the assembly pre-processing
          # step. cmake and go are NOT required for non-FIPS builds.
          nativeBuildInputs = with pkgs; [
            perl
          ];

          # Platform-specific system libraries.
          buildInputs = with pkgs; lib.optionals stdenv.isDarwin [
            darwin.apple_sdk.frameworks.Security
            darwin.apple_sdk.frameworks.SystemConfiguration
          ];

          # Suppress NixOS-injected RUSTFLAGS that may conflict with aws-lc-rs
          # (e.g. -C target-cpu=x86-64-v4 requires AVX-512 which is not
          # universally available).
          RUSTFLAGS = "";

          meta = {
            description = "Purpose-built SSH transport client for Git hosting services";
            homepage    = "https://github.com/steelbore/gitssh";
            license     = pkgs.lib.licenses.gpl3Plus;
            maintainers = [ ];
            mainProgram = "gitway";
            platforms   = pkgs.lib.platforms.unix ++ pkgs.lib.platforms.windows;
          };
        };
      in
      {
        # ── Packages ───────────────────────────────────────────────────────────
        packages = {
          gitway  = gitway;
          default = gitway;
        };

        # ── Run ────────────────────────────────────────────────────────────────
        apps.default = flake-utils.lib.mkApp {
          drv  = gitway;
          name = "gitway";
        };

        # ── Development shell ──────────────────────────────────────────────────
        # Supersedes shell.nix; shell.nix delegates here for backward
        # compatibility with `nix-shell` users.
        devShells.default = pkgs.mkShell {
          name = "gitway-dev";

          nativeBuildInputs = with pkgs; [
            # Rust toolchain via rustup so developers can pin versions freely.
            rustup

            # Required by the aws-lc-rs crate (assembly pre-processing).
            perl

            # C toolchain for linking.
            gcc

            # Optional: strip release binaries.
            binutils

            # Convenience: git, cargo-edit, etc.
            git
          ];

          # Override NixOS-injected flags that break aws-lc-rs:
          # -flto=auto can fail during C compilation of the crypto backend.
          # -C target-cpu=x86-64-v4 requires AVX-512 (not universal).
          CFLAGS    = "-march=native -O2 -pipe";
          RUSTFLAGS = "-C target-cpu=native";

          shellHook = ''
            # Unset any inherited RUSTFLAGS from the parent NixOS environment
            # before applying ours, so they don't stack.
            unset RUSTFLAGS
            export RUSTFLAGS="-C target-cpu=native"
            echo "gitway dev shell ready. Run: cargo build --release"
          '';
        };
      }
    );
}
