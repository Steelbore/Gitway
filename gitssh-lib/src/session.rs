// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! SSH session management (FR-1 through FR-5, FR-9 through FR-17).
//!
//! [`GitsshSession`] wraps a russh [`client::Handle`] and exposes the
//! operations Gitssh needs: connect, authenticate, exec, and close.
//!
//! Host-key verification is performed inside [`GitsshHandler::check_server_key`]
//! using the fingerprints collected by [`crate::hostkey`].

use std::borrow::Cow;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg};
use russh::{Disconnect, Preferred, cipher, kex};

use crate::config::GitsshConfig;
use crate::error::{GitsshError, GitsshErrorKind};
use crate::hostkey;
use crate::relay;

// ── Handler ───────────────────────────────────────────────────────────────────

/// russh client event handler.
///
/// Validates the server host key (FR-6, FR-7, FR-8) and captures any
/// authentication banner the server sends before confirming the session.
struct GitsshHandler {
    /// Expected SHA-256 fingerprints for the target host.
    fingerprints: Vec<String>,
    /// When `true`, host-key verification is skipped (FR-8).
    skip_check: bool,
    /// Buffer for the last authentication banner received from the server.
    ///
    /// GitHub sends "Hi <user>! You've successfully authenticated…" here.
    auth_banner: Arc<Mutex<Option<String>>>,
}

impl fmt::Debug for GitsshHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitsshHandler")
            .field("fingerprints", &self.fingerprints)
            .field("skip_check", &self.skip_check)
            .field("auth_banner", &self.auth_banner)
            .finish()
    }
}

impl client::Handler for GitsshHandler {
    type Error = GitsshError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        if self.skip_check {
            log::warn!("host-key verification skipped (--insecure-skip-host-check)");
            return Ok(true);
        }

        let fp = server_public_key
            .fingerprint(HashAlg::Sha256)
            .to_string();

        log::debug!("session: checking server host key {fp}");

        if self.fingerprints.iter().any(|f| f == &fp) {
            log::debug!("session: host key verified: {fp}");
            Ok(true)
        } else {
            Err(GitsshError::host_key_mismatch(fp))
        }
    }

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let trimmed = banner.trim().to_owned();
        log::info!("server banner: {banner}");
        if let Ok(mut guard) = self.auth_banner.lock() {
            *guard = Some(trimmed);
        }
        Ok(())
    }
}

// ── Session ───────────────────────────────────────────────────────────────────

/// An active SSH session connected to a GitHub (or GHE) host.
///
/// # Typical Usage
///
/// ```no_run
/// use gitssh_lib::{GitsshConfig, GitsshSession};
///
/// # async fn doc() -> Result<(), gitssh_lib::GitsshError> {
/// let config = GitsshConfig::github();
/// let mut session = GitsshSession::connect(&config).await?;
/// // authenticate, exec, close…
/// # Ok(())
/// # }
/// ```
pub struct GitsshSession {
    handle: client::Handle<GitsshHandler>,
    /// Authentication banner received from the server, if any.
    auth_banner: Arc<Mutex<Option<String>>>,
}

/// Manual Debug impl because `client::Handle<H>` does not implement `Debug`.
impl fmt::Debug for GitsshSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitsshSession").finish_non_exhaustive()
    }
}

impl GitsshSession {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Establishes a TCP connection to the host in `config` and completes the
    /// SSH handshake (including host-key verification).
    ///
    /// Does **not** authenticate; call [`authenticate`](Self::authenticate) or
    /// [`authenticate_best`](Self::authenticate_best) after this.
    ///
    /// # Errors
    ///
    /// Returns an error on network failure or if the server's host key does not
    /// match any pinned fingerprint.
    pub async fn connect(config: &GitsshConfig) -> Result<Self, GitsshError> {
        let russh_cfg = Arc::new(build_russh_config(config.inactivity_timeout));
        let fingerprints =
            hostkey::fingerprints_for_host(&config.host, &config.custom_known_hosts)?;
        let auth_banner = Arc::new(Mutex::new(None));

        let handler = GitsshHandler {
            fingerprints,
            skip_check: config.skip_host_check,
            auth_banner: Arc::clone(&auth_banner),
        };

        log::debug!("session: connecting to {}:{}", config.host, config.port);

        let handle = client::connect(
            russh_cfg,
            (config.host.as_str(), config.port),
            handler,
        )
        .await?;

        log::debug!("session: SSH handshake complete with {}", config.host);

        Ok(Self { handle, auth_banner })
    }

    // ── Authentication ────────────────────────────────────────────────────────

    /// Authenticates with an explicit key.
    ///
    /// Use [`authenticate_best`] to let the library discover the key
    /// automatically.
    ///
    /// # Errors
    ///
    /// Returns an error on SSH protocol failures.  Returns
    /// [`GitsshError::is_authentication_failed`] when the server accepts the
    /// exchange but rejects the key.
    pub async fn authenticate(
        &mut self,
        username: &str,
        key: PrivateKeyWithHashAlg,
    ) -> Result<(), GitsshError> {
        log::debug!("session: authenticating as {username}");

        let result = self.handle.authenticate_publickey(username, key).await?;

        if result.success() {
            log::debug!("session: authentication succeeded for {username}");
            Ok(())
        } else {
            Err(GitsshError::authentication_failed())
        }
    }

    /// Authenticates with a private key and an accompanying OpenSSH certificate
    /// (FR-12).
    ///
    /// The certificate is presented to the server in place of the raw public
    /// key.  This is typically used with organisation-issued certificates that
    /// grant access without requiring the public key to be listed in
    /// `authorized_keys`.
    ///
    /// # Errors
    ///
    /// Returns an error on SSH protocol failures or if the server rejects the
    /// certificate.
    pub async fn authenticate_with_cert(
        &mut self,
        username: &str,
        key: russh::keys::PrivateKey,
        cert: russh::keys::Certificate,
    ) -> Result<(), GitsshError> {
        log::debug!("session: authenticating as {username} with OpenSSH certificate");

        let result = self
            .handle
            .authenticate_openssh_cert(username, Arc::new(key), cert)
            .await?;

        if result.success() {
            log::debug!("session: certificate authentication succeeded for {username}");
            Ok(())
        } else {
            Err(GitsshError::authentication_failed())
        }
    }

    /// Discovers the best available key and authenticates using it.
    ///
    /// Priority order (FR-9):
    /// 1. Explicit `--identity` path from config.
    /// 2. Default `.ssh` paths (`id_ed25519` → `id_ecdsa` → `id_rsa`).
    /// 3. SSH agent via `$SSH_AUTH_SOCK` (Unix only).
    ///
    /// If a certificate path is configured in `config.cert_file`, certificate
    /// authentication (FR-12) is used instead of raw public-key authentication
    /// for file-based keys.
    ///
    /// When the chosen key requires a passphrase this method returns an error
    /// whose [`is_key_encrypted`](GitsshError::is_key_encrypted) predicate is
    /// `true`; the caller (CLI layer) should then prompt and call
    /// [`authenticate_with_passphrase`](Self::authenticate_with_passphrase).
    ///
    /// # Errors
    ///
    /// Returns [`GitsshError::is_no_key_found`] when no key is available via
    /// any discovery method.
    pub async fn authenticate_best(&mut self, config: &GitsshConfig) -> Result<(), GitsshError> {
        use crate::auth::{IdentityResolution, find_identity, wrap_key};

        let resolution = find_identity(config)?;

        match resolution {
            IdentityResolution::Found { key, .. } => {
                return self.auth_key_or_cert(config, key).await;
            }
            IdentityResolution::Encrypted { path } => {
                log::debug!(
                    "session: key at {} is passphrase-protected; trying SSH agent first",
                    path.display()
                );
                // Try the agent before asking for a passphrase.  The key may
                // already be loaded via `ssh-add`, and a passphrase prompt is
                // impossible when gitssh is spawned by Git without a terminal.
                #[cfg(unix)]
                {
                    use crate::auth::connect_agent;
                    if let Some(conn) = connect_agent().await? {
                        match self.authenticate_with_agent(&config.username, conn).await {
                            Ok(()) => return Ok(()),
                            Err(e) if e.is_authentication_failed() => {
                                log::debug!(
                                    "session: agent could not authenticate; \
                                     will request passphrase for {}",
                                    path.display()
                                );
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
                return Err(GitsshError::new(GitsshErrorKind::Keys(
                    russh::keys::Error::KeyIsEncrypted,
                )));
            }
            IdentityResolution::NotFound => {
                // Fall through to agent (below).
            }
        }

        // Priority 3: SSH agent — reached only when no file-based key exists (FR-9).
        #[cfg(unix)]
        {
            use crate::auth::connect_agent;
            if let Some(conn) = connect_agent().await? {
                return self.authenticate_with_agent(&config.username, conn).await;
            }
        }

        // For RSA keys, ask the server which hash algorithm it prefers (FR-11).
        // This branch is only reached when we must still try a key via wrap_key
        // after exhausting the above — currently unused, but kept for clarity.
        let _ = wrap_key; // suppress unused-import warning on non-Unix builds
        Err(GitsshError::no_key_found())
    }

    /// Loads an encrypted key with `passphrase` and authenticates.
    ///
    /// Call this after [`authenticate_best`] returns an encrypted-key error
    /// and the CLI has collected the passphrase from the terminal.
    ///
    /// If `config.cert_file` is set, certificate authentication is used
    /// (FR-12).
    ///
    /// # Errors
    ///
    /// Returns an error if the passphrase is wrong or authentication fails.
    pub async fn authenticate_with_passphrase(
        &mut self,
        config: &GitsshConfig,
        path: &std::path::Path,
        passphrase: &str,
    ) -> Result<(), GitsshError> {
        use crate::auth::load_encrypted_key;

        let key = load_encrypted_key(path, passphrase)?;
        self.auth_key_or_cert(config, key).await
    }

    /// Tries each identity held in `conn` until one succeeds or all are
    /// exhausted.
    ///
    /// On Unix this is called automatically by [`authenticate_best`] when no
    /// file-based key is found.  For plain public-key identities the signing
    /// challenge is forwarded to the agent; for certificate identities the
    /// full certificate is presented alongside the agent-signed challenge.
    ///
    /// # Errors
    ///
    /// Returns [`GitsshError::is_authentication_failed`] if all identities are
    /// rejected, or [`GitsshError::is_no_key_found`] if the agent was empty.
    #[cfg(unix)]
    pub async fn authenticate_with_agent(
        &mut self,
        username: &str,
        mut conn: crate::auth::AgentConnection,
    ) -> Result<(), GitsshError> {
        use russh::keys::agent::AgentIdentity;

        for identity in conn.identities.clone() {
            let result = match &identity {
                AgentIdentity::PublicKey { key, .. } => {
                    let hash_alg = if key.algorithm().is_rsa() {
                        self.handle
                            .best_supported_rsa_hash()
                            .await?
                            .flatten()
                            // Fall back to SHA-256 when the server offers no guidance (FR-11).
                            .or(Some(HashAlg::Sha256))
                    } else {
                        None
                    };
                    self.handle
                        .authenticate_publickey_with(
                            username,
                            key.clone(),
                            hash_alg,
                            &mut conn.client,
                        )
                        .await
                        .map_err(GitsshError::from)
                }
                AgentIdentity::Certificate { certificate, .. } => {
                    self.handle
                        .authenticate_certificate_with(
                            username,
                            certificate.clone(),
                            None,
                            &mut conn.client,
                        )
                        .await
                        .map_err(GitsshError::from)
                }
            };

            match result? {
                r if r.success() => {
                    log::debug!("session: agent authentication succeeded");
                    return Ok(());
                }
                _ => {
                    log::debug!("session: agent identity rejected; trying next");
                }
            }
        }

        Err(GitsshError::no_key_found())
    }

    // ── Exec / relay ──────────────────────────────────────────────────────────

    /// Opens a session channel, executes `command`, and relays stdio
    /// bidirectionally until the remote process exits.
    ///
    /// Returns the remote exit code (FR-16).  Exit-via-signal returns
    /// `128 + signal_number` (FR-17).
    ///
    /// # Errors
    ///
    /// Returns an error on channel open failure or SSH protocol errors.
    pub async fn exec(&mut self, command: &str) -> Result<u32, GitsshError> {
        log::debug!("session: opening exec channel for '{command}'");

        let channel = self.handle.channel_open_session().await?;
        channel.exec(true, command).await?;

        let exit_code = relay::relay_channel(channel).await?;

        log::debug!("session: command '{command}' exited with code {exit_code}");

        Ok(exit_code)
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /// Sends a graceful `SSH_MSG_DISCONNECT` and closes the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the disconnect message cannot be sent.
    pub async fn close(self) -> Result<(), GitsshError> {
        self.handle
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Returns the authentication banner last received from the server (if any).
    ///
    /// For GitHub.com this contains the "Hi <user>!" welcome message.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned, which can only occur if another
    /// thread panicked while holding the lock — a programming error.
    #[must_use]
    pub fn auth_banner(&self) -> Option<String> {
        self.auth_banner
            .lock()
            .expect("auth_banner lock is not poisoned")
            .clone()
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Authenticates with `key`, using certificate auth if `config.cert_file`
    /// is set (FR-12), otherwise plain public-key auth (FR-11).
    async fn auth_key_or_cert(
        &mut self,
        config: &GitsshConfig,
        key: russh::keys::PrivateKey,
    ) -> Result<(), GitsshError> {
        use crate::auth::{load_cert, wrap_key};

        if let Some(ref cert_path) = config.cert_file {
            let cert = load_cert(cert_path)?;
            return self
                .authenticate_with_cert(&config.username, key, cert)
                .await;
        }

        // For RSA keys, ask the server which hash algorithm it prefers (FR-11).
        let rsa_hash = if key.algorithm().is_rsa() {
            self.handle
                .best_supported_rsa_hash()
                .await?
                .flatten()
                .or(Some(HashAlg::Sha256))
        } else {
            None
        };

        let wrapped = wrap_key(key, rsa_hash);
        self.authenticate(&config.username, wrapped).await
    }
}

// ── russh config builder ──────────────────────────────────────────────────────

/// Constructs a russh [`client::Config`] with Gitssh's preferred algorithms.
///
/// Algorithm preferences (FR-2, FR-3, FR-4):
/// - Key exchange: `curve25519-sha256` (RFC 8731) with
///   `curve25519-sha256@libssh.org` as fallback.
/// - Cipher: `chacha20-poly1305@openssh.com`.
/// - `ext-info-c` advertises server-sig-algs extension support.
fn build_russh_config(inactivity_timeout: Duration) -> client::Config {
    client::Config {
        // 60 s matches GitHub's server-side idle threshold.
        // Lowering below ~10 s risks spurious timeouts on high-latency links.
        inactivity_timeout: Some(inactivity_timeout),
        preferred: Preferred {
            kex: Cow::Owned(vec![
                kex::CURVE25519,              // curve25519-sha256 (RFC 8731)
                kex::CURVE25519_PRE_RFC_8731, // curve25519-sha256@libssh.org
                kex::EXTENSION_SUPPORT_AS_CLIENT, // ext-info-c (FR-4)
            ]),
            cipher: Cow::Owned(vec![
                cipher::CHACHA20_POLY1305, // chacha20-poly1305@openssh.com (FR-3)
            ]),
            ..Default::default()
        },
        ..Default::default()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── NFR-6: legacy algorithm exclusion ────────────────────────────────────

    /// 3DES-CBC must never appear in the negotiated cipher list (NFR-6).
    ///
    /// Our explicit cipher override contains only chacha20-poly1305, so 3DES
    /// cannot be selected even if the server offers it.
    #[test]
    fn config_cipher_excludes_3des() {
        let config = build_russh_config(Duration::from_secs(60));
        let found = config.preferred.cipher.iter().any(|c| c.as_ref() == "3des-cbc");
        assert!(!found, "3DES-CBC must not appear in the cipher list (NFR-6)");
    }

    /// DSA must never appear in the key-algorithm list (NFR-6).
    ///
    /// russh's `Preferred::DEFAULT` already omits DSA; this test locks that
    /// invariant so a russh upgrade cannot silently re-introduce it.
    #[test]
    fn config_key_algorithms_exclude_dsa() {
        use russh::keys::Algorithm;

        let config = build_russh_config(Duration::from_secs(60));
        assert!(
            !config.preferred.key.contains(&Algorithm::Dsa),
            "DSA must not appear in the key-algorithm list (NFR-6)"
        );
    }

    // ── FR-2 / FR-3 positive assertions ─────────────────────────────────────

    /// curve25519-sha256 must be in the kex list (FR-2).
    #[test]
    fn config_kex_includes_curve25519() {
        let config = build_russh_config(Duration::from_secs(60));
        let found = config.preferred.kex.iter().any(|k| k.as_ref() == "curve25519-sha256");
        assert!(found, "curve25519-sha256 must be in the kex list (FR-2)");
    }

    /// chacha20-poly1305@openssh.com must be in the cipher list (FR-3).
    #[test]
    fn config_cipher_includes_chacha20_poly1305() {
        let config = build_russh_config(Duration::from_secs(60));
        let found = config
            .preferred
            .cipher
            .iter()
            .any(|c| c.as_ref() == "chacha20-poly1305@openssh.com");
        assert!(found, "chacha20-poly1305@openssh.com must be in the cipher list (FR-3)");
    }
}
