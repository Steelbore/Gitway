// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Subprocess integration tests for M18 — Connection Retry, Backoff, and
//! Timeouts (PRD §5.8.7, FR-80..FR-83).
//!
//! Tests are grouped into three areas:
//!
//! 1. **Flag acceptance** — `--connect-timeout`, `--attempts`, and
//!    `--max-retry-window` are accepted by the argument parser.  Clap
//!    parse failures exit without printing a `gitway diag` line; Gitway
//!    application errors (including the expected "no fingerprints for
//!    host" failure) always emit one.  The presence of `gitway diag ts=`
//!    in stderr therefore confirms the flag was recognised by clap.
//!
//! 2. **Timeout enforcement** — a local TCP listener that accepts the
//!    connection but never sends the SSH banner is used to stall the
//!    handshake.  `--connect-timeout 2 --attempts 1` must cancel the
//!    attempt within a generous wall-clock budget.
//!
//! 3. **JSON error envelope** — `--test --json` with the new flags must
//!    emit a well-formed `{"error": {...}}` blob on stderr when the
//!    connection fails; no panic.
//!
//! # Design notes
//!
//! `gitway` is compiled with `allow_hyphen_values = true` (OpenSSH
//! compatibility) and the positional `<HOST>` argument is defined with
//! `index = 1` only — there is **no** `--host` long-name flag in the
//! `Cli` struct.  Passing `--host nonexistent` would be swallowed as the
//! positional host value due to `allow_hyphen_values = true`, producing
//! "no fingerprints for host '--host'" rather than connecting to the
//! intended hostname.  All tests in this module therefore pass hostnames
//! as a bare positional argument (e.g. `"127.0.0.1"` or
//! `"nonexistent.invalid.example.test"`), not with a `--host` prefix.
//!
//! Verifying `retry_attempts` inside a *successful* `--test --json`
//! envelope requires a live SSH server and is covered by the end-to-end
//! matrix in CI, not here.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

fn gitway() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gitway"))
}

/// Strips agent-detection environment variables so the auto-JSON trigger on
/// CI / agent hosts does not interfere with tests that assert on human-mode
/// output.  Returns the augmented [`Command`].
fn strip_agent_env(cmd: &mut Command) -> &mut Command {
    cmd.env_remove("AI_AGENT")
        .env_remove("AGENT")
        .env_remove("CI")
        .env_remove("CLAUDECODE")
        .env_remove("CURSOR_AGENT")
        .env_remove("GEMINI_CLI")
}

/// Asserts that a CLI flag was accepted by clap (not silently rejected as an
/// unknown flag).
///
/// Clap parse failures exit immediately without running any Gitway logic, so
/// they never emit the `gitway diag ts=` diagnostic line that Gitway's error
/// handler always appends.  Checking for that line confirms that clap
/// successfully parsed the flag and Gitway ran far enough to hit a
/// Gitway-level error (e.g., "no fingerprints for host").
///
/// # Note on exit code 2
///
/// **Do not** use `exit_code != 2` as the discriminator here.  Gitway uses
/// exit code 2 for its own `USAGE_ERROR` class (including host-fingerprint
/// configuration errors), so code 2 is *expected* — it does **not** indicate
/// a clap parse failure.
fn assert_flag_accepted(output: &std::process::Output, flag: &str) {
    assert!(
        output.status.code().is_some(),
        "{flag}: process terminated by signal",
    );
    assert!(
        !output.status.success(),
        "{flag}: gitway unexpectedly succeeded with an unknown host",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);

    // `gitway diag ts=` is emitted by Gitway's error handler — only reachable
    // AFTER clap parsing succeeds.  Its presence proves the flag was accepted.
    assert!(
        stderr.contains("gitway diag ts="),
        "{flag}: stderr missing 'gitway diag ts=' — \
         the flag may have caused a clap parse error before Gitway ran; \
         stderr={stderr}",
    );
}

/// Searches `stderr` for the last non-empty line that starts with `{` and
/// returns it.  Used to locate the JSON error blob which may be preceded by
/// ANSI-coloured tracing output.
fn find_json_blob(stderr: &str) -> Option<&str> {
    stderr
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
}

// ── Magic values ─────────────────────────────────────────────────────────────

/// Per-attempt connect timeout used in the enforcement test, in seconds.
///
/// 2 s is long enough to be reliable on loaded CI nodes but short enough
/// that the overall test finishes quickly.
const CONNECT_TIMEOUT_SECS: u64 = 2;

/// Wall-clock budget for the enforcement test.
///
/// Must comfortably exceed `CONNECT_TIMEOUT_SECS` plus process-spawn and
/// tokio-runtime startup overhead.  12 s gives a generous ×6 margin over
/// the 2-s per-attempt timeout.
const ENFORCEMENT_BUDGET: Duration = Duration::from_secs(12);

/// Background thread sleep duration — keeps the accepted TCP socket open
/// long enough that the `gitway` process's own connect-timeout fires first.
const BACKGROUND_HOLD_SECS: u64 = 60;

// ── 1. Flag-acceptance tests ──────────────────────────────────────────────────

/// Verifies `--connect-timeout SECONDS` is recognised by the argument parser
/// (FR-80).
///
/// The invocation will fail at Gitway's own host-fingerprint check (no entry
/// for the dummy host in `known_hosts`), but `gitway diag ts=` will appear in
/// stderr, confirming clap accepted the flag.
#[test]
fn connect_timeout_flag_accepted() {
    let mut cmd = Command::new(gitway());
    strip_agent_env(&mut cmd);
    let output = cmd
        .args([
            "--connect-timeout",
            "5",
            "nonexistent.invalid.example.test",
            "git-upload-pack",
            "foo.git",
        ])
        .output()
        .expect("spawn gitway");

    assert_flag_accepted(&output, "--connect-timeout");
}

/// Verifies `--attempts N` is recognised by the argument parser (FR-80).
#[test]
fn attempts_flag_accepted() {
    let mut cmd = Command::new(gitway());
    strip_agent_env(&mut cmd);
    let output = cmd
        .args([
            "--attempts",
            "1",
            "nonexistent.invalid.example.test",
            "git-upload-pack",
            "foo.git",
        ])
        .output()
        .expect("spawn gitway");

    assert_flag_accepted(&output, "--attempts");
}

/// Verifies `--max-retry-window SECONDS` is recognised by the argument parser
/// (FR-81).
#[test]
fn max_retry_window_flag_accepted() {
    let mut cmd = Command::new(gitway());
    strip_agent_env(&mut cmd);
    let output = cmd
        .args([
            "--max-retry-window",
            "30",
            "nonexistent.invalid.example.test",
            "git-upload-pack",
            "foo.git",
        ])
        .output()
        .expect("spawn gitway");

    assert_flag_accepted(&output, "--max-retry-window");
}

// ── 2. Timeout enforcement ────────────────────────────────────────────────────

/// Binds a local TCP port, accepts the connection, but never writes the SSH
/// banner.  Asserts that `--connect-timeout 2 --attempts 1` cancels the
/// attempt and the process exits within `ENFORCEMENT_BUDGET`.
///
/// This verifies FR-80's per-attempt deadline wraps the full `connect()`
/// future (including the SSH handshake layer), not just the TCP three-way
/// handshake.
///
/// # Host argument
///
/// The host `127.0.0.1` is passed as a **bare positional argument** (index 1
/// in the `Cli` struct), not as `--host 127.0.0.1`.  Gitway's `Cli` has
/// `allow_hyphen_values = true` for OpenSSH compatibility and no `--host`
/// long-name flag; passing `--host 127.0.0.1` would make `"--host"` the
/// positional host value and `"127.0.0.1"` the command.
#[test]
fn connect_timeout_fires_before_ssh_banner() {
    // Bind an ephemeral port on the loopback interface.  The OS completes the
    // TCP three-way handshake (connection appears established to the caller)
    // before `accept()` is called, so gitway's TCP connect succeeds almost
    // immediately.  The background thread accepts and holds the stream open
    // but never writes, stalling the SSH protocol layer until the
    // `connect_timeout` fires.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener
        .local_addr()
        .expect("local_addr on bound listener")
        .port();

    std::thread::spawn(move || {
        if let Ok((_stream, _peer)) = listener.accept() {
            // Keep `_stream` alive so the OS does not send RST while gitway
            // is waiting for the SSH banner.  The process exits (and the
            // thread is torn down) well before the sleep expires.
            std::thread::sleep(Duration::from_secs(BACKGROUND_HOLD_SECS));
        }
        // `listener` is dropped here (moved into the closure).
    });

    let start = Instant::now();

    let output = Command::new(gitway())
        .args([
            "--connect-timeout",
            &CONNECT_TIMEOUT_SECS.to_string(),
            "--attempts",
            "1",
            "--no-config",
            "--insecure-skip-host-check",
            "--test",
            "--port",
            &port.to_string(),
            // Host passed positionally (index 1) — see module-level note.
            "127.0.0.1",
        ])
        .output()
        .expect("spawn gitway");

    let elapsed = start.elapsed();

    assert!(
        !output.status.success(),
        "gitway unexpectedly succeeded against a silent TCP listener",
    );
    assert!(
        elapsed < ENFORCEMENT_BUDGET,
        "connect-timeout ({CONNECT_TIMEOUT_SECS} s) did not fire within \
         the {ENFORCEMENT_BUDGET:?} budget; elapsed={elapsed:.2?}; \
         stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
}

/// With `--attempts 1` to a host that fails with a transient DNS error, the
/// process must exit without performing any retry backoff delay.  Asserts the
/// process returns quickly (well within a 15-second budget; DNS NXDOMAIN is
/// typically < 5 s).
///
/// This is a sanity-check that `--attempts 1` suppresses the retry loop
/// rather than sleeping through backoff cycles before failing (FR-80).
#[test]
fn attempts_one_skips_retry_delay() {
    // 15 s is generous even on slow CI — a single DNS NXDOMAIN lookup for a
    // non-existent domain typically resolves in under 3 s.
    const BUDGET: Duration = Duration::from_secs(15);

    let start = Instant::now();

    let mut cmd = Command::new(gitway());
    strip_agent_env(&mut cmd);
    let output = cmd
        .args([
            "--attempts",
            "1",
            "--no-config",
            "nonexistent.invalid.example.test",
            "git-upload-pack",
            "foo.git",
        ])
        .output()
        .expect("spawn gitway");

    let elapsed = start.elapsed();

    // Confirm the flag was accepted (see `assert_flag_accepted` for rationale).
    assert_flag_accepted(&output, "--attempts 1");
    assert!(
        elapsed < BUDGET,
        "--attempts 1 did not suppress retry backoff; elapsed={elapsed:.2?}",
    );
}

// ── 3. JSON error envelope ────────────────────────────────────────────────────

/// Verifies that `--test --json` with the M18 flags emits a well-formed
/// `{"error": {...}}` blob on stderr when the connection fails.
///
/// Stderr may be prefixed by ANSI-coloured tracing log lines (from the
/// default `tracing-subscriber` formatter).  The test locates the last line
/// starting with `{` to extract the JSON blob before asserting its shape.
///
/// This exercises the JSON error-output path (SFRS Rule 1) together with
/// the new retry/timeout CLI flags (FR-80, FR-83) and confirms no panic
/// occurs on the failure path.
#[test]
fn test_json_error_has_error_key_when_connect_fails() {
    // Host passed positionally — see module-level note about `--host`.
    let output = Command::new(gitway())
        .args([
            "--test",
            "--json",
            "--connect-timeout",
            "3",
            "--attempts",
            "1",
            // Positional host at index 1.
            "nonexistent.invalid.example.test",
        ])
        .output()
        .expect("spawn gitway");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"error\""),
        "--test --json must emit a structured error blob on stderr; \
         stderr={stderr:?}",
    );

    // Stderr may be prefixed by tracing log lines (ANSI-coloured).  Extract
    // the last `{...}` line and parse that as the JSON error envelope.
    let json_line = find_json_blob(&stderr)
        .unwrap_or_else(|| panic!("no JSON blob found in stderr; stderr={stderr:?}"));

    let blob: serde_json::Value = serde_json::from_str(json_line).unwrap_or_else(|e| {
        panic!(
            "JSON blob is not valid JSON (SFRS Rule 1 violation): {e}; \
             line={json_line:?}"
        )
    });

    assert!(
        blob.get("error").is_some(),
        "JSON blob missing top-level \"error\" key: {blob}",
    );
}

/// Verifies that the error path does not accidentally include a
/// `retry_attempts` key — that field belongs only to the success `data`
/// envelope (FR-83).
///
/// If the error blob happens to be absent or malformed, the test skips the
/// assertion (the shape assertion in `test_json_error_has_error_key_when_connect_fails`
/// already guards the happy parse path).
#[test]
fn test_json_error_path_does_not_include_retry_attempts() {
    // Host passed positionally — see module-level note about `--host`.
    let output = Command::new(gitway())
        .args([
            "--test",
            "--json",
            "--connect-timeout",
            "2",
            "--attempts",
            "1",
            // Positional host at index 1.
            "nonexistent.invalid.example.test",
        ])
        .output()
        .expect("spawn gitway");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Extract the JSON line (if any) and verify the error object does not
    // carry a `retry_attempts` field.
    if let Some(json_line) = find_json_blob(&stderr) {
        if let Ok(blob) = serde_json::from_str::<serde_json::Value>(json_line) {
            if let Some(error_obj) = blob.get("error") {
                assert!(
                    error_obj.get("retry_attempts").is_none(),
                    "error blob must not include `retry_attempts` \
                     (that key belongs to the success data envelope); \
                     blob={blob}",
                );
            }
        }
    }
}
