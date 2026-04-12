// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Identity resolution (FR-9 through FR-12).
//!
//! Key discovery follows a fixed priority order:
//!
//! 1. **CLI `--identity` flag** — explicit path from the user.
//! 2. **Default `.ssh` paths** — `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`,
//!    `~/.ssh/id_rsa` (in that order, matching modern OpenSSH defaults).
//! 3. **SSH agent** — contacted via `$SSH_AUTH_SOCK` (Unix) (FR-9).
//!
//! If a key file is encrypted, [`IdentityResolution::Encrypted`] is returned so
//! the caller (the CLI) can prompt for a passphrase without this library
//! depending on terminal I/O.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg};

use crate::config::GitsshConfig;
use crate::error::{GitsshError, GitsshErrorKind};

// ── Public resolution result ───────────────────────────────────────────────���──

/// Result returned by [`find_identity`].
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "IdentityResolution is short-lived (created once per session on the \
              non-hot auth path); boxing PrivateKey would harm ergonomics with no \
              measurable benefit."
)]
pub enum IdentityResolution {
    /// A key was loaded and is ready to use.
    Found {
        /// The loaded private key.
        key: PrivateKey,
        /// Path from which the key was loaded (for logging / error messages).
        path: PathBuf,
    },
    /// A key file was found but is passphrase-protected.
    Encrypted {
        /// Path to the encrypted key file.
        path: PathBuf,
    },
    /// No usable key was found on any file path.
    NotFound,
}

// ── SSH agent connection (Unix only) ─────────────────────────────────────────

/// A live connection to an SSH agent with its advertised identities.
///
/// Obtained via [`connect_agent`].  The connection is used by
/// [`GitsshSession::authenticate_with_agent`] to sign authentication
/// challenges without ever loading the private key material into this process.
#[cfg(unix)]
pub struct AgentConnection {
    /// The underlying agent client over the Unix-domain socket.
    pub client: russh::keys::agent::client::AgentClient<tokio::net::UnixStream>,
    /// Identities advertised by the agent (public keys and/or certificates).
    pub identities: Vec<russh::keys::agent::AgentIdentity>,
}

#[cfg(unix)]
impl fmt::Debug for AgentConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentConnection")
            .field("identities", &self.identities)
            .finish_non_exhaustive()
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Searches for an identity key according to FR-9 priority order.
///
/// Returns [`IdentityResolution::Encrypted`] rather than prompting for a
/// passphrase; the caller is responsible for prompting and calling
/// [`load_encrypted_key`] with the result.
///
/// SSH agent fallback is handled separately by [`connect_agent`] and
/// [`GitsshSession::authenticate_with_agent`]; this function covers only
/// file-based identities.
///
/// # Errors
///
/// Returns an error only for unexpected failures (permission denied, corrupt
/// key data, etc.).  A missing or encrypted key is not an error at this stage.
pub fn find_identity(config: &GitsshConfig) -> Result<IdentityResolution, GitsshError> {
    // Priority 1: explicit --identity path.
    if let Some(ref path) = config.identity_file {
        return probe_key(path);
    }

    // Priority 2: well-known default paths.
    for path in default_key_paths() {
        if !path.exists() {
            continue;
        }
        match probe_key(&path)? {
            IdentityResolution::NotFound => {}
            found => return Ok(found),
        }
    }

    Ok(IdentityResolution::NotFound)
}

/// Loads a passphrase-protected key file with the supplied passphrase.
///
/// Use this after receiving [`IdentityResolution::Encrypted`] and prompting
/// the user with `rpassword` (or equivalent) in the CLI layer.
///
/// # Errors
///
/// Returns an error if the passphrase is wrong or the file cannot be read.
pub fn load_encrypted_key(path: &Path, passphrase: &str) -> Result<PrivateKey, GitsshError> {
    russh::keys::load_secret_key(path, Some(passphrase)).map_err(GitsshError::from)
}

/// Loads an OpenSSH certificate from `path` (FR-12).
///
/// The certificate is presented alongside the private key during
/// [`GitsshSession::authenticate_with_cert`].
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not a valid OpenSSH
/// certificate.
pub fn load_cert(path: &Path) -> Result<russh::keys::Certificate, GitsshError> {
    russh::keys::load_openssh_certificate(path)
        .map_err(|e| GitsshError::from(russh::keys::Error::from(e)))
}

/// Wraps a [`PrivateKey`] with the appropriate RSA hash algorithm.
///
/// For RSA keys, `rsa_hash` should be the result of
/// [`Handle::best_supported_rsa_hash`](russh::client::Handle::best_supported_rsa_hash)
/// (falling back to `SHA-256` if the query fails or returns `None`).
/// For all other key types the `hash_alg` field is ignored by russh.
#[must_use]
pub fn wrap_key(key: PrivateKey, rsa_hash: Option<HashAlg>) -> PrivateKeyWithHashAlg {
    PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash)
}

/// Attempts to connect to the SSH agent via `$SSH_AUTH_SOCK` and retrieve its
/// advertised identities (FR-9, priority 3).
///
/// Returns `Ok(None)` when:
/// - `SSH_AUTH_SOCK` is not set in the environment.
/// - The socket file does not exist (agent not running).
/// - The agent holds no identities.
///
/// Returns `Err` only for unexpected I/O or protocol failures.
///
/// # Errors
///
/// Returns an error on socket read/write failures after a connection has been
/// established.
#[cfg(unix)]
pub async fn connect_agent() -> Result<Option<AgentConnection>, GitsshError> {
    use russh::keys::agent::client::AgentClient;

    let mut client = match AgentClient::connect_env().await {
        Ok(c) => c,
        Err(russh::keys::Error::EnvVar(_)) => {
            log::debug!("auth: SSH_AUTH_SOCK not set; skipping agent");
            return Ok(None);
        }
        Err(russh::keys::Error::BadAuthSock) => {
            log::debug!("auth: SSH_AUTH_SOCK socket not found; skipping agent");
            return Ok(None);
        }
        Err(e) => return Err(GitsshError::from(e)),
    };

    let identities = client
        .request_identities()
        .await
        .map_err(GitsshError::from)?;

    if identities.is_empty() {
        log::debug!("auth: SSH agent has no identities");
        return Ok(None);
    }

    log::debug!(
        "auth: SSH agent offered {} identity/identities",
        identities.len()
    );
    Ok(Some(AgentConnection { client, identities }))
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns the ordered list of default key paths to probe.
///
/// Ed25519 is checked first to prefer the most secure modern key type.
/// Legacy DSA is intentionally excluded (NFR-6).
fn default_key_paths() -> Vec<PathBuf> {
    let Some(home) = dirs::home_dir() else {
        log::warn!("auth: could not determine home directory; skipping default key paths");
        return Vec::new();
    };

    let ssh = home.join(".ssh");
    vec![
        ssh.join("id_ed25519"),
        ssh.join("id_ecdsa"),
        ssh.join("id_rsa"),
    ]
}

/// Attempts to load a key from `path` without a passphrase.
///
/// Returns:
/// - `Found` if the key loaded successfully.
/// - `Encrypted` if the key exists but needs a passphrase.
/// - `NotFound` if the file does not exist.
/// - `Err` on any other failure.
fn probe_key(path: &Path) -> Result<IdentityResolution, GitsshError> {
    match russh::keys::load_secret_key(path, None) {
        Ok(key) => {
            log::debug!("auth: loaded identity key from {}", path.display());
            Ok(IdentityResolution::Found {
                key,
                path: path.to_owned(),
            })
        }
        Err(russh::keys::Error::KeyIsEncrypted) => {
            log::debug!(
                "auth: identity key at {} is passphrase-protected",
                path.display()
            );
            Ok(IdentityResolution::Encrypted {
                path: path.to_owned(),
            })
        }
        Err(russh::keys::Error::CouldNotReadKey) => {
            // Treat unreadable-for-unknown-reason the same as absent.
            Ok(IdentityResolution::NotFound)
        }
        Err(russh::keys::Error::IO(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            // File does not exist — not an error at probe time.
            Ok(IdentityResolution::NotFound)
        }
        Err(e) => Err(GitsshError::new(GitsshErrorKind::Keys(e))),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── find_identity / probe_key ─────────────────────────────────────────────

    #[test]
    fn explicit_nonexistent_path_returns_not_found() {
        let config = GitsshConfig::builder("github.com")
            .identity_file("/tmp/gitssh_test_nonexistent_key_xyz")
            .build();
        let result = find_identity(&config).unwrap();
        assert!(matches!(result, IdentityResolution::NotFound));
    }

    #[test]
    fn explicit_path_takes_priority_over_defaults() {
        // Point --identity at a nonexistent file; find_identity must probe
        // only that path and return NotFound — it must NOT fall through to
        // the default ~/.ssh search.
        let config = GitsshConfig::builder("github.com")
            .identity_file("/tmp/gitssh_test_explicit_priority_xyz")
            .build();
        let result = find_identity(&config).unwrap();
        // The file doesn't exist so we get NotFound, but crucially the
        // function must return at priority 1 without touching ~/.ssh.
        assert!(
            matches!(result, IdentityResolution::NotFound),
            "explicit path must short-circuit default search"
        );
    }

    #[test]
    fn no_identity_file_falls_through_to_defaults() {
        // Without --identity, find_identity walks ~/.ssh/*.  Even if no key
        // is present, it must return NotFound (not panic or error).
        let config = GitsshConfig::builder("github.com").build();
        let result = find_identity(&config);
        assert!(
            result.is_ok(),
            "missing default keys must yield Ok(NotFound), not Err"
        );
    }

    // ── load_cert ─────────────────────────────────────────────────────────────

    #[test]
    fn load_cert_nonexistent_file_returns_error() {
        let result = load_cert(Path::new("/tmp/gitssh_test_nonexistent_cert_xyz.pub"));
        assert!(result.is_err(), "loading a missing cert must return Err");
    }

    // ── default_key_paths ─────────────────────────────────────────────────────

    #[test]
    fn default_key_paths_order_is_ed25519_ecdsa_rsa() {
        let paths = default_key_paths();
        // Home dir may be unavailable in some CI environments; skip if so.
        if paths.is_empty() {
            return;
        }
        assert_eq!(paths.len(), 3);
        assert!(
            paths[0].ends_with("id_ed25519"),
            "first path must be id_ed25519"
        );
        assert!(
            paths[1].ends_with("id_ecdsa"),
            "second path must be id_ecdsa"
        );
        assert!(paths[2].ends_with("id_rsa"), "third path must be id_rsa");
    }
}
