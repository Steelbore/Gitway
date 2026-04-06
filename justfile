# SPDX-License-Identifier: GPL-3.0-or-later
# Build recipes for Gitssh.
#
# Prerequisites: gcc and nasm must be in PATH.
# On NixOS: `nix-shell -p gcc -p nasm` (or keep a persistent shell).
#
# RUSTFLAGS is unset before every cargo invocation because the NixOS shell
# exports -C target-cpu=x86-64-v4 which requires AVX-512.  Without unsetting
# it, build scripts SIGILL on CPUs that only have AVX2 (e.g. i7-8665U).
# The .cargo/config.toml [build].rustflags provides -C target-cpu=native
# once the env var is gone.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Default: build debug binary
[group('build')]
build:
    unset RUSTFLAGS; cargo build

# Build optimised release binary
[group('build')]
release:
    unset RUSTFLAGS; cargo build --release

# Run all unit tests
[group('test')]
test:
    unset RUSTFLAGS; cargo test

# Run integration tests (requires real GitHub connectivity and a valid SSH key)
[group('test')]
test-integration:
    unset RUSTFLAGS; GITSSH_INTEGRATION_TESTS=1 cargo test

# Lint with clippy (all workspace crates)
[group('lint')]
lint:
    unset RUSTFLAGS; cargo clippy --all-targets -- -D warnings

# Format check
[group('lint')]
fmt:
    cargo fmt --all -- --check

# Apply formatting
[group('lint')]
fmt-fix:
    cargo fmt --all

# Remove build artefacts
[group('misc')]
clean:
    cargo clean
