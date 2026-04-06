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

use gitssh_lib::{GitsshConfig, GitsshSession};

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
/// Does **not** authenticate; this only exercises the TLS/KEX handshake.
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

    use gitssh_lib::hostkey;

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
