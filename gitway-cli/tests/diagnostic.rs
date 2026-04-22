// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration tests for the single-line failure diagnostic.
//!
//! Every Gitway binary, when it fails in human mode, emits one logfmt-style
//! stderr record of the shape:
//!
//! ```text
//! gitway diag ts=2026-04-22T18:43:11Z pid=12345 code=4 reason=PERMISSION_DENIED argv=["gitway", ...]
//! ```
//!
//! These tests spawn each compiled binary with an invalid input so it
//! fails deterministically and asserts:
//!
//! 1. The `gitway diag` line appears exactly once on stderr.
//! 2. It carries non-empty `ts=`, `pid=`, `code=`, `reason=`, and `argv=`
//!    fields.
//! 3. JSON mode (`--json`) suppresses the diagnostic line; the structured
//!    `{"error": {...}}` blob already carries `timestamp` and `command`.
//!
//! All failure paths used here are local (unknown hostname, missing key
//! file) — no network, no OpenSSH dependency.

use std::path::PathBuf;
use std::process::Command;

fn gitway() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gitway"))
}

fn gitway_keygen() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gitway-keygen"))
}

fn gitway_add() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gitway-add"))
}

/// Counts lines in `text` that begin with the `gitway diag ts=` marker.
fn count_diag_lines(text: &str) -> usize {
    text.lines()
        .filter(|line| line.starts_with("gitway diag ts="))
        .count()
}

/// Returns the first `gitway diag` line in `text`, or panics.
fn first_diag_line(text: &str) -> &str {
    text.lines()
        .find(|line| line.starts_with("gitway diag ts="))
        .expect("expected one `gitway diag` line on stderr")
}

/// Asserts that `diag_line` carries the required logfmt fields.
fn assert_diag_shape(diag_line: &str, expected_argv0_suffix: &str) {
    assert!(diag_line.contains(" ts="), "missing ts=: {diag_line}");
    assert!(diag_line.contains(" pid="), "missing pid=: {diag_line}");
    assert!(diag_line.contains(" code="), "missing code=: {diag_line}");
    assert!(
        diag_line.contains(" reason="),
        "missing reason=: {diag_line}"
    );
    assert!(diag_line.contains(" argv=["), "missing argv=[: {diag_line}");
    assert!(
        diag_line.contains(expected_argv0_suffix),
        "argv missing expected binary {expected_argv0_suffix:?}: {diag_line}"
    );
}

// ── gitway (transport) ───────────────────────────────────────────────────────

#[test]
fn transport_human_mode_emits_one_diag_line() {
    let output = Command::new(gitway())
        .args([
            "nonexistent.invalid.example.test",
            "git-upload-pack",
            "foo.git",
        ])
        .output()
        .expect("failed to run gitway");

    assert!(
        !output.status.success(),
        "gitway unexpectedly succeeded with unknown host"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        count_diag_lines(&stderr),
        1,
        "expected exactly one `gitway diag` line; stderr={stderr:?}"
    );
    assert_diag_shape(first_diag_line(&stderr), "gitway");
}

#[test]
fn transport_json_mode_suppresses_diag_line() {
    let output = Command::new(gitway())
        .args([
            "--json",
            "nonexistent.invalid.example.test",
            "git-upload-pack",
            "foo.git",
        ])
        .output()
        .expect("failed to run gitway");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        count_diag_lines(&stderr),
        0,
        "JSON mode must not emit a diag line; stderr={stderr:?}"
    );
    // And the structured error blob is still there.
    assert!(
        stderr.contains("\"error\""),
        "JSON mode must emit a structured error blob; stderr={stderr:?}"
    );
}

// ── gitway-keygen shim ───────────────────────────────────────────────────────

#[test]
fn gitway_keygen_missing_file_emits_diag_line() {
    let output = Command::new(gitway_keygen())
        .args(["-f", "/steelbore/does-not-exist-gitway-diag-test", "-l"])
        .output()
        .expect("failed to run gitway-keygen");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        count_diag_lines(&stderr),
        1,
        "expected exactly one `gitway diag` line; stderr={stderr:?}"
    );
    assert_diag_shape(first_diag_line(&stderr), "gitway-keygen");
}

// ── gitway-add shim ──────────────────────────────────────────────────────────

#[test]
fn gitway_add_missing_file_emits_diag_line() {
    let output = Command::new(gitway_add())
        .arg("/steelbore/does-not-exist-gitway-diag-test")
        .output()
        .expect("failed to run gitway-add");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        count_diag_lines(&stderr),
        1,
        "expected exactly one `gitway diag` line; stderr={stderr:?}"
    );
    assert_diag_shape(first_diag_line(&stderr), "gitway-add");
}
