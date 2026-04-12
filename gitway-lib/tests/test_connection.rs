// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration tests — real connections to github.com.
//!
//! These tests require network access and a valid SSH identity key.  They are
//! gated behind the `GITSSH_INTEGRATION_TESTS` environment variable; set it to
//! any non-empty value to run them:
//!
//! ```shell
//! GITSSH_INTEGRATION_TESTS=1 cargo test --test test_connection
//! ```
//!
//! The tests are intentionally excluded from the default `cargo test` run to
//! avoid flaky failures in CI environments that lack network access or keys.

use std::time::{Duration, Instant};

use gitssh_lib::{GitsshConfig, GitsshSession, hostkey};

/// Returns `true` when integration tests are enabled.
fn integration_enabled() -> bool {
    std::env::var("GITSSH_INTEGRATION_TESTS")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

// ── Connectivity tests ────────────────────────────────────────────────────────

/// Verifies that gitssh can establish a TCP connection and pass host-key
/// verification against the live github.com server.
///
/// Does **not** authenticate; this only exercises the TCP/KEX handshake.
#[tokio::test]
async fn connect_to_github_verifies_host_key() {
    if !integration_enabled() {
        return;
    }

    let config = GitsshConfig::github();
    let session = GitsshSession::connect(&config)
        .await
        .expect("connection and host-key verification must succeed");

    session
        .close()
        .await
        .expect("graceful disconnect must succeed");
}

/// Verifies that a deliberate host-key mismatch is correctly rejected.
///
/// Uses `--insecure-skip-host-check` on a fresh connection to confirm the
/// server is reachable, then attempts a new connection with a fabricated
/// fingerprint list to assert the mismatch path fires.
#[tokio::test]
async fn host_key_mismatch_is_rejected() {
    if !integration_enabled() {
        return;
    }

    // A fingerprint that will never match any real GitHub key.
    let fake_fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    // Verify the server is actually reachable first.
    let reachability_config = GitsshConfig::builder("github.com")
        .skip_host_check(true)
        .build();
    let _s = GitsshSession::connect(&reachability_config)
        .await
        .expect("server must be reachable");

    // Now attempt a connection with the fake fingerprint via a custom
    // known_hosts file written to a temporary path.
    let tmp = tempfile::NamedTempFile::new().expect("temp file");
    std::fs::write(tmp.path(), format!("github.com {fake_fp}\n"))
        .expect("write temp known_hosts");

    let config = GitsshConfig::builder("github.com")
        .custom_known_hosts(tmp.path())
        .build();

    let result = GitsshSession::connect(&config).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.is_host_key_mismatch(),
        "expected host-key-mismatch error, got: {err}"
    );
    _ = hostkey::DEFAULT_GITHUB_HOST; // ensure import is used
}

/// Verifies that `--insecure-skip-host-check` allows the connection through
/// even when no fingerprints are configured.
#[tokio::test]
async fn insecure_skip_host_check_bypasses_verification() {
    if !integration_enabled() {
        return;
    }

    let config = GitsshConfig::builder("github.com")
        .skip_host_check(true)
        .build();

    let session = GitsshSession::connect(&config)
        .await
        .expect("connection must succeed with skip_host_check");

    session.close().await.expect("disconnect must succeed");
}

// ── Cold-start timing test (NFR-1) ────────────────────────────────────────────

/// Measures the wall-clock time from process start to completed SSH handshake
/// (NFR-1: target ≤ 2 s on a 50 ms RTT link).
///
/// The test fails hard if the connection takes longer than 10 seconds, which
/// would indicate a systemic issue (DNS failure, firewall, etc.) rather than
/// a performance regression.  The actual measured time is printed so it can
/// be compared against the 2 s NFR target in CI logs.
///
/// **Note:** This measures wall-clock time including DNS resolution and TCP
/// setup.  It cannot enforce the exact 50 ms RTT assumption from the NFR, but
/// it provides a meaningful baseline signal in CI.
#[tokio::test]
async fn cold_start_handshake_is_fast() {
    // Hard limit: anything beyond 10 s is a definite regression.
    // Soft target per NFR-1: ≤ 2 s on a 50 ms RTT link.
    const HARD_LIMIT: Duration = Duration::from_secs(10);

    if !integration_enabled() {
        return;
    }

    let config = GitsshConfig::github();

    let t0 = Instant::now();
    let session = GitsshSession::connect(&config)
        .await
        .expect("connection must succeed for timing test");
    let elapsed = t0.elapsed();

    session.close().await.expect("disconnect must succeed");

    eprintln!(
        "cold-start handshake: {:.0} ms  (NFR-1 target: ≤ 2000 ms)",
        elapsed.as_secs_f64() * 1000.0
    );

    assert!(
        elapsed <= HARD_LIMIT,
        "cold-start took {elapsed:?}, exceeding the {HARD_LIMIT:?} hard limit"
    );
}
