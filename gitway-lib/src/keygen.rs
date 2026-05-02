// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-21
//! OpenSSH key generation, loading, and fingerprinting.
//!
//! Pure-Rust via the [`ssh-key`] crate. Generated keys are written in the
//! standard OpenSSH private-key format (PEM-armored, PKCS#8-style) and the
//! accompanying public key in the single-line `authorized_keys` format.
//!
//! # Examples
//!
//! ```no_run
//! use std::path::Path;
//! use gitway_lib::keygen::{KeyType, generate, write_keypair};
//!
//! let key = generate(KeyType::Ed25519, None, "user@host").unwrap();
//! write_keypair(&key, Path::new("/tmp/id_ed25519"), None).unwrap();
//! ```
//!
//! # Errors
//!
//! All operations return [`GitwayError`]. Cryptographic failures (RNG,
//! encryption) and I/O failures are both folded into that type; the caller
//! distinguishes via the `is_*` predicates.
//!
//! # Zeroization
//!
//! `ssh_key::PrivateKey` holds its secret scalar inside a type that
//! zeroes itself on drop. Passphrase material supplied to
//! [`write_keypair`] and [`change_passphrase`] is passed by reference
//! wrapped in [`Zeroizing`] so the caller retains ownership of the
//! zeroization lifecycle.

use std::fs;
#[cfg(unix)]
use std::io::Write as _;
use std::path::{Path, PathBuf};

use rand_core::OsRng;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use crate::GitwayError;

// ── Public types ──────────────────────────────────────────────────────────────

/// The set of key algorithms `gitway keygen` can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Ed25519 (default; fixed 256-bit).
    Ed25519,
    /// ECDSA over NIST P-256.
    EcdsaP256,
    /// ECDSA over NIST P-384.
    EcdsaP384,
    /// ECDSA over NIST P-521.
    EcdsaP521,
    /// RSA. Bit length is selected by the `bits` argument to [`generate`].
    Rsa,
}

impl KeyType {
    /// Returns the canonical textual name used on the `ssh-keygen -t` CLI.
    #[must_use]
    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::EcdsaP256 | Self::EcdsaP384 | Self::EcdsaP521 => "ecdsa",
            Self::Rsa => "rsa",
        }
    }
}

// ── Generation ────────────────────────────────────────────────────────────────

/// Generates a new keypair of the requested type.
///
/// For ECDSA, the curve is selected by the `KeyType` variant; `bits` is
/// ignored. For RSA, `bits` defaults to 3072 (the OpenSSH minimum
/// recommended value as of 2025). Ed25519 always produces a 256-bit key.
///
/// # Errors
///
/// Returns [`GitwayError::signing`] on RNG failure or on an invalid
/// `bits` value (for RSA: below 2048 or above 16384).
pub fn generate(
    kind: KeyType,
    bits: Option<u32>,
    comment: &str,
) -> Result<PrivateKey, GitwayError> {
    let algorithm = match kind {
        KeyType::Ed25519 => Algorithm::Ed25519,
        KeyType::EcdsaP256 => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        KeyType::EcdsaP384 => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        KeyType::EcdsaP521 => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        },
        KeyType::Rsa => {
            let b = bits.unwrap_or(DEFAULT_RSA_BITS);
            if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&b) {
                return Err(GitwayError::invalid_config(format!(
                    "RSA key size {b} is out of range ({MIN_RSA_BITS}-{MAX_RSA_BITS})"
                )));
            }
            return generate_rsa(b, comment);
        }
    };

    let mut rng = OsRng;
    let mut key = PrivateKey::random(&mut rng, algorithm)
        .map_err(|e| GitwayError::signing(format!("key generation failed: {e}")))?;
    key.set_comment(comment);
    Ok(key)
}

/// Generates an RSA private key of the requested size.
fn generate_rsa(bits: u32, comment: &str) -> Result<PrivateKey, GitwayError> {
    // `ssh_key::PrivateKey::random` does not support RSA directly; build it
    // via ssh_key::private::RsaKeypair::random and wrap. This path only
    // compiles with the `rsa` feature on `ssh-key`.
    let mut rng = OsRng;
    let usize_bits = usize::try_from(bits)
        .map_err(|_e| GitwayError::invalid_config(format!("RSA bit count {bits} is too large")))?;
    let rsa_key = ssh_key::private::RsaKeypair::random(&mut rng, usize_bits)
        .map_err(|e| GitwayError::signing(format!("RSA key generation failed: {e}")))?;
    let mut key = PrivateKey::from(rsa_key);
    key.set_comment(comment);
    Ok(key)
}

/// The default RSA modulus size for new keys.
const DEFAULT_RSA_BITS: u32 = 3072;
/// Minimum RSA modulus size accepted by `gitway keygen`.
///
/// OpenSSH's `ssh-keygen` allows 1024, but NIST SP 800-131A deprecates it and
/// GitHub's key-upload endpoint rejects it.
const MIN_RSA_BITS: u32 = 2048;
/// Upper bound chosen to match OpenSSH's `ssh-keygen` behaviour (16384).
const MAX_RSA_BITS: u32 = 16384;

// ── Writing ───────────────────────────────────────────────────────────────────

/// Writes a keypair to disk.
///
/// Two files are created:
///
/// | Path | Contents | Unix mode |
/// |------|----------|-----------|
/// | `path` | OpenSSH private key (optionally encrypted) | 0600 |
/// | `path.pub` | OpenSSH public key (`authorized_keys` line) | 0644 |
///
/// If `passphrase` is `Some`, the private key is encrypted before writing.
/// Passing `Some(empty_string)` is rejected — use `None` for an unencrypted
/// key.
///
/// # Errors
///
/// Returns [`GitwayError`] on I/O failure, encryption failure, or when the
/// output parent directory does not exist.
pub fn write_keypair(
    key: &PrivateKey,
    path: &Path,
    passphrase: Option<&Zeroizing<String>>,
) -> Result<(), GitwayError> {
    let key_to_write = match passphrase {
        Some(pp) if pp.is_empty() => {
            return Err(GitwayError::invalid_config(
                "empty passphrase is not allowed — pass `None` to leave the key unencrypted",
            ));
        }
        Some(pp) => {
            let mut rng = OsRng;
            key.encrypt(&mut rng, pp.as_bytes())
                .map_err(|e| GitwayError::signing(format!("failed to encrypt private key: {e}")))?
        }
        None => key.clone(),
    };

    let private_pem = key_to_write
        .to_openssh(LineEnding::LF)
        .map_err(|e| GitwayError::signing(format!("failed to serialize private key: {e}")))?;
    write_private_file(path, private_pem.as_bytes())?;

    let public = key.public_key();
    let public_line = public
        .to_openssh()
        .map_err(|e| GitwayError::signing(format!("failed to serialize public key: {e}")))?;
    let pub_path = pub_path_for(path);
    let mut out = String::with_capacity(public_line.len() + 1);
    out.push_str(&public_line);
    out.push('\n');
    fs::write(&pub_path, out.as_bytes())?;
    Ok(())
}

/// Writes the private-key bytes to `path` with a restrictive permission mode.
///
/// On Unix the file mode is set to `0o600` (owner read/write only). On other
/// platforms this is a plain write — file-system access controls are the
/// user's responsibility.
#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), GitwayError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        // `mode` is honored only on create; permissions on an existing file
        // are left alone. The 0o600 constant matches OpenSSH's ssh-keygen.
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), GitwayError> {
    fs::write(path, bytes)?;
    Ok(())
}

/// Returns the companion `.pub` path for a private key at `path`.
fn pub_path_for(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(".pub");
    PathBuf::from(os)
}

// ── Passphrase management ─────────────────────────────────────────────────────

/// Changes (or adds, or removes) the passphrase on an existing OpenSSH private key.
///
/// - `old`: the current passphrase, or `None` if the key is unencrypted.
/// - `new`: the target passphrase, or `None` to remove encryption.
///
/// # Errors
///
/// Returns [`GitwayError`] if the old passphrase is wrong, the key cannot be
/// read, or the new key cannot be written.
pub fn change_passphrase(
    path: &Path,
    old: Option<&Zeroizing<String>>,
    new: Option<&Zeroizing<String>>,
) -> Result<(), GitwayError> {
    let pem = fs::read_to_string(path)?;
    let loaded = PrivateKey::from_openssh(&pem)
        .map_err(|e| GitwayError::signing(format!("failed to parse existing key: {e}")))?;

    let decrypted = if loaded.is_encrypted() {
        let pp = old.ok_or_else(|| {
            GitwayError::invalid_config(
                "existing key is encrypted but no old passphrase was provided",
            )
        })?;
        loaded
            .decrypt(pp.as_bytes())
            .map_err(|e| GitwayError::signing(format!("old passphrase is wrong: {e}")))?
    } else {
        loaded
    };

    write_keypair(&decrypted, path, new)
}

// ── Fingerprinting ────────────────────────────────────────────────────────────

/// Returns the OpenSSH-style fingerprint string for a public key.
///
/// Uses `SHA256:<base64>` — the format OpenSSH has emitted by default since
/// version 6.8 (2015).
#[must_use]
pub fn fingerprint(public: &PublicKey, hash: HashAlg) -> String {
    public.fingerprint(hash).to_string()
}

// ── Public-key extraction ─────────────────────────────────────────────────────

/// Extracts the public key from a private-key file and writes it to `out`.
///
/// If `out` is `None`, the public key is written to `<path>.pub`.
/// Passphrase handling: if the private key is encrypted, `passphrase` must
/// be supplied. Public-key extraction does not strictly require decryption
/// (the public part is stored alongside the private), so an unencrypted
/// `.pub` is still produced.
///
/// # Errors
///
/// Returns [`GitwayError`] on I/O or parsing failure.
pub fn extract_public(path: &Path, out: Option<&Path>) -> Result<(), GitwayError> {
    let pem = fs::read_to_string(path)?;
    let key = PrivateKey::from_openssh(&pem)
        .map_err(|e| GitwayError::signing(format!("failed to parse private key: {e}")))?;
    let public_line = key
        .public_key()
        .to_openssh()
        .map_err(|e| GitwayError::signing(format!("failed to serialize public key: {e}")))?;
    let target = match out {
        Some(p) => p.to_owned(),
        None => pub_path_for(path),
    };
    let mut buf = String::with_capacity(public_line.len() + 1);
    buf.push_str(&public_line);
    buf.push('\n');
    fs::write(&target, buf.as_bytes())?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_ed25519_has_expected_algorithm() {
        let key = generate(KeyType::Ed25519, None, "test").unwrap();
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
        assert_eq!(key.comment(), "test");
    }

    #[test]
    fn generate_ecdsa_p256_has_expected_curve() {
        let key = generate(KeyType::EcdsaP256, None, "test").unwrap();
        assert_eq!(
            key.algorithm(),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256
            }
        );
    }

    #[test]
    fn write_and_read_roundtrip_unencrypted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        let key = generate(KeyType::Ed25519, None, "roundtrip@test").unwrap();
        write_keypair(&key, &path, None).unwrap();

        let pem = fs::read_to_string(&path).unwrap();
        let loaded = PrivateKey::from_openssh(&pem).unwrap();
        assert!(!loaded.is_encrypted());
        assert_eq!(
            loaded.public_key().fingerprint(HashAlg::Sha256),
            key.public_key().fingerprint(HashAlg::Sha256)
        );

        let pub_path = path.with_extension("pub");
        assert!(pub_path.exists(), "expected companion .pub file");
        let pub_content = fs::read_to_string(&pub_path).unwrap();
        assert!(pub_content.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn write_and_read_roundtrip_encrypted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        let key = generate(KeyType::Ed25519, None, "enc@test").unwrap();
        let pp = Zeroizing::new(String::from("correcthorse"));
        write_keypair(&key, &path, Some(&pp)).unwrap();

        let pem = fs::read_to_string(&path).unwrap();
        let loaded = PrivateKey::from_openssh(&pem).unwrap();
        assert!(loaded.is_encrypted());
        let decrypted = loaded.decrypt(pp.as_bytes()).unwrap();
        assert_eq!(decrypted.comment(), "enc@test");
    }

    #[test]
    fn rejects_empty_passphrase() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        let key = generate(KeyType::Ed25519, None, "empty@test").unwrap();
        let pp = Zeroizing::new(String::new());
        let err = write_keypair(&key, &path, Some(&pp)).unwrap_err();
        assert!(err.to_string().contains("empty passphrase"));
    }

    #[test]
    fn change_passphrase_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        let key = generate(KeyType::Ed25519, None, "change@test").unwrap();
        let pp1 = Zeroizing::new(String::from("one"));
        write_keypair(&key, &path, Some(&pp1)).unwrap();

        let pp2 = Zeroizing::new(String::from("two"));
        change_passphrase(&path, Some(&pp1), Some(&pp2)).unwrap();

        // Wrong old-passphrase should now fail.
        let err = change_passphrase(&path, Some(&pp1), Some(&pp2)).unwrap_err();
        assert!(err.to_string().contains("passphrase"));

        // Right one works.
        change_passphrase(&path, Some(&pp2), None).unwrap();
        let pem = fs::read_to_string(&path).unwrap();
        let loaded = PrivateKey::from_openssh(&pem).unwrap();
        assert!(!loaded.is_encrypted());
    }

    #[test]
    fn fingerprint_format_is_sha256() {
        let key = generate(KeyType::Ed25519, None, "fp@test").unwrap();
        let fp = fingerprint(key.public_key(), HashAlg::Sha256);
        assert!(fp.starts_with("SHA256:"));
    }

    #[test]
    fn extract_public_matches_companion_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        let key = generate(KeyType::Ed25519, None, "ext@test").unwrap();
        write_keypair(&key, &path, None).unwrap();

        let pub_path_side = dir.path().join("side.pub");
        extract_public(&path, Some(&pub_path_side)).unwrap();

        let pub_from_generate = fs::read_to_string(path.with_extension("pub")).unwrap();
        let pub_from_extract = fs::read_to_string(&pub_path_side).unwrap();
        assert_eq!(
            pub_from_generate.split_whitespace().nth(1),
            pub_from_extract.split_whitespace().nth(1),
            "base64 key body should match"
        );
    }

    #[test]
    fn rsa_size_bounds_are_enforced() {
        let err = generate(KeyType::Rsa, Some(1024), "rsa@test").unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }
}
