// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-05
//! Steady-state throughput benchmark (NFR-2, S1).
//!
//! Measures wall-clock time for a complete connect → authenticate → exec →
//! close cycle against GitHub, and compares against an equivalent OpenSSH
//! invocation.
//!
//! # Running
//!
//! ```sh
//! GITWAY_INTEGRATION_TESTS=1 cargo bench --bench throughput
//! ```
//!
//! Requires a GitHub SSH key discoverable by the standard search order (or
//! `SSH_AUTH_SOCK`).  Without `GITWAY_INTEGRATION_TESTS=1` the benchmark
//! body is a no-op so it can appear in CI without credentials.
//!
//! # Interpreting results
//!
//! Criterion prints median wall-clock time in nanoseconds.  Compare the
//! `gitway_exec` and `openssh_exec` groups; the ratio should be ≤ 1.05
//! (within 5 % of OpenSSH, S1).

use std::process::Command;
use std::time::Instant;

use criterion::{Criterion, criterion_group, criterion_main};
use gitway_lib::{GitwayConfig, GitwaySession};

/// Returns `true` when the integration environment variable is set.
fn integration_enabled() -> bool {
    std::env::var("GITWAY_INTEGRATION_TESTS").is_ok_and(|v| v == "1")
}

/// Benchmark: full connect → `authenticate_best` → exec → close.
///
/// Exercises the complete cold-start path so we measure the same work that
/// `ssh -T git@github.com` would perform.
fn bench_gitway_exec(c: &mut Criterion) {
    if !integration_enabled() {
        return;
    }

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    c.bench_function("gitway_exec", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = GitwayConfig::github();
                let mut session = GitwaySession::connect(&config)
                    .await
                    .expect("gitway connect");
                session
                    .authenticate_best(&config)
                    .await
                    .expect("gitway auth");
                // `true` exits immediately with code 1; we only care about
                // the round-trip timing, not the exit code.
                let _ = session.exec("true").await;
                session.close().await.expect("gitway close");
            });
        });
    });
}

/// Benchmark: equivalent OpenSSH invocation for comparison.
///
/// Runs `ssh -T git@github.com` and measures wall-clock time. This is the
/// S1 baseline; Gitssh must be within 5 % of this value.
fn bench_openssh_exec(c: &mut Criterion) {
    if !integration_enabled() {
        return;
    }

    // Verify openssh is available; skip silently if not.
    if Command::new("ssh").arg("-V").output().is_err() {
        return;
    }

    c.bench_function("openssh_exec", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let t0 = Instant::now();
                let _ = Command::new("ssh")
                    .args(["-o", "BatchMode=yes", "-T", "git@github.com"])
                    .output();
                total += t0.elapsed();
            }
            total
        });
    });
}

criterion_group!(benches, bench_gitway_exec, bench_openssh_exec);
criterion_main!(benches);
