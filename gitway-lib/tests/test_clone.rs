// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration tests — end-to-end `git clone` via `GIT_SSH_COMMAND=gitway`.
//!
//! These tests exercise the full transport relay (FR-14 through FR-17) by
//! cloning a real GitHub repository through the `gitway` binary.
//!
//! **Prerequisites:**
//! - The `gitway` binary must be built (`cargo build`).
//! - A valid SSH identity key must be accessible.
//! - Network access to `github.com:22` must be available.
//!
//! Gate with the `GITWAY_INTEGRATION_TESTS` environment variable:
//!
//! ```shell
//! GITWAY_INTEGRATION_TESTS=1 cargo test --test test_clone
//! ```

use std::path::PathBuf;

/// Returns `true` when integration tests are enabled.
fn integration_enabled() -> bool {
    std::env::var("GITWAY_INTEGRATION_TESTS")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

/// Returns the path to the `gitway` debug binary in the Cargo target directory.
///
/// Uses `CARGO_MANIFEST_DIR` to locate the workspace root reliably regardless
/// of the working directory from which tests are invoked.
fn gitway_binary() -> PathBuf {
    // CARGO_MANIFEST_DIR points to gitway-lib; walk up one level to the
    // workspace root, then into target/debug.
    let manifest = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set by Cargo"),
    );
    manifest
        .parent()
        .expect("workspace root must exist")
        .join("target/debug/gitway")
}

// ── Clone tests ───────────────────────────────────────────────────────────────

/// Clones a small public GitHub repository into a temporary directory using
/// `gitway` as the SSH transport.
///
/// Verifies that:
/// - The full transport relay works end-to-end (FR-14 through FR-17).
/// - The cloned directory contains a `.git/` subdirectory.
/// - The `git clone` exit code is 0.
///
/// Uses `github.com/steelbore/gitssh` (this repository) as the test target
/// since it is always accessible and small.
#[test]
fn git_clone_via_gitway_succeeds() {
    if !integration_enabled() {
        return;
    }

    let binary = gitway_binary();
    assert!(
        binary.exists(),
        "gitway binary not found at {}; run `cargo build` first",
        binary.display()
    );

    let tmp = tempfile::TempDir::new().expect("temp dir");
    let dest = tmp.path().join("repo");

    let status = std::process::Command::new("git")
        .args([
            "clone",
            "--depth=1",
            "git@github.com:steelbore/gitssh.git",
            dest.to_str().expect("UTF-8 path"),
        ])
        .env("GIT_SSH_COMMAND", binary.to_str().expect("UTF-8 path"))
        // Suppress git's progress output so test output stays clean.
        .env("GIT_TERMINAL_PROMPT", "0")
        .status()
        .expect("git must be installed");

    assert!(
        status.success(),
        "git clone via gitway must exit with code 0, got: {status}"
    );
    assert!(
        dest.join(".git").is_dir(),
        ".git directory must exist in the cloned repo"
    );
}

/// Verifies that `git clone` fails gracefully when no valid SSH key is
/// available, producing a non-zero exit code without a panic or hang.
///
/// Uses a temporary `HOME` directory with no `.ssh/` contents to simulate
/// a machine with no identity.
#[test]
fn git_clone_without_key_exits_nonzero() {
    if !integration_enabled() {
        return;
    }

    let binary = gitway_binary();
    assert!(
        binary.exists(),
        "gitway binary not found at {}; run `cargo build` first",
        binary.display()
    );

    let tmp_home = tempfile::TempDir::new().expect("temp home dir");
    let tmp_dest = tempfile::TempDir::new().expect("temp dest dir");

    let status = std::process::Command::new("git")
        .args([
            "clone",
            "--depth=1",
            "git@github.com:steelbore/gitssh.git",
            tmp_dest.path().join("repo").to_str().expect("UTF-8 path"),
        ])
        .env("GIT_SSH_COMMAND", binary.to_str().expect("UTF-8 path"))
        .env("GIT_TERMINAL_PROMPT", "0")
        // Override HOME so no default keys and no SSH_AUTH_SOCK are visible.
        .env("HOME", tmp_home.path())
        .env_remove("SSH_AUTH_SOCK")
        .status()
        .expect("git must be installed");

    assert!(
        !status.success(),
        "git clone without a key must exit non-zero"
    );
}
