// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-05
//! Fuzz target: custom known-hosts file parser.
//!
//! Exercises `anvil_ssh::hostkey::fingerprints_for_host` by writing
//! arbitrary bytes to a temporary file and passing it as a custom
//! known-hosts path.
//!
//! The parser splits on newlines and spaces; this target focuses on
//! malformed lines, Unicode edge cases, and embedded null bytes.

#![forbid(unsafe_code)]

use std::io::Write as _;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Write the fuzz bytes to a temp file.
    let Ok(mut file) = tempfile::NamedTempFile::new() else {
        return;
    };
    if file.write_all(data).is_err() {
        return;
    }

    let path = file.path().to_path_buf();

    // Ask for fingerprints of a GHE hostname via the fuzzed file.
    // The result is discarded; we only require no panic.
    let _ = anvil_ssh::hostkey::fingerprints_for_host(
        "fuzz.example.com",
        &Some(path),
    );
});
