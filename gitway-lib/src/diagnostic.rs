// SPDX-License-Identifier: GPL-3.0-or-later
//! Single-line failure diagnostic for every Gitway binary.
//!
//! When a Gitway binary runs and fails in human (non-JSON) mode, one
//! [`emit`] or [`emit_for`] call writes a logfmt-style record to stderr:
//!
//! ```text
//! gitway diag ts=2026-04-22T18:43:11Z pid=12345 code=4 reason=PERMISSION_DENIED argv=["gitway", "git@github.com", "git-upload-pack", "'org/repo.git'"]
//! ```
//!
//! The point is to turn silent `exit 128` failures — the opaque code git
//! reports when `core.sshCommand` fails — into a single grep-able line
//! that carries enough context to triage: ISO 8601 timestamp, PID, argv,
//! exit code, and a short error reason.
//!
//! JSON mode already carries `timestamp` and `command` in its structured
//! `{"error": {...}}` blob, so callers should skip this helper on that
//! path.  Stdout is always left untouched (SFRS Rule 1) — the diagnostic
//! writes exclusively to stderr.

use crate::error::GitwayError;
use crate::time::now_iso8601;

/// Emits the single-line diagnostic record with an explicit exit code and
/// a reason string.  Use this from the shim binaries (`gitway-keygen`,
/// `gitway-add`) where the reason codes are selected from a local static
/// table; use [`emit_for`] when a [`GitwayError`] is already in hand.
pub fn emit(code: u32, reason: &str) {
    let argv: Vec<String> = std::env::args().collect();
    eprintln!(
        "gitway diag ts={ts} pid={pid} code={code} reason={reason} argv={argv:?}",
        ts = now_iso8601(),
        pid = std::process::id(),
    );
}

/// Emits the diagnostic record for a [`GitwayError`], reusing the error's
/// mapped exit code and string error class.
pub fn emit_for(err: &GitwayError) {
    emit(err.exit_code(), err.error_code());
}
