// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-05
//! Fuzz target: OpenSSH private key parsing.
//!
//! Exercises `russh::keys::decode_secret_key` with arbitrary bytes and
//! ensures Gitssh's key-loading path never panics or produces undefined
//! behaviour regardless of input.
//!
//! The target passes arbitrary bytes directly to the key decoder.  Encrypted
//! keys are attempted without a passphrase (they should return an error, not
//! panic).  The fuzz corpus should be seeded with real OpenSSH private keys
//! of each type (Ed25519, ECDSA, RSA) to improve coverage.

#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Interpret the bytes as a UTF-8 PEM string (most OpenSSH keys are PEM).
    // Invalid UTF-8 is caught early and skipped — the interesting cases are
    // valid UTF-8 that looks almost-but-not-quite like an OpenSSH key.
    let Ok(pem) = std::str::from_utf8(data) else {
        return;
    };

    // Attempt to decode as an unencrypted key.  The result is intentionally
    // discarded; we only care that no panic occurs.
    let _ = russh::keys::decode_secret_key(pem, None);

    // Also attempt with a dummy passphrase to exercise the encrypted path.
    let _ = russh::keys::decode_secret_key(pem, Some("passphrase"));
});
