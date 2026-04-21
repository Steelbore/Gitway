// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-21
//! Long-lived SSH agent daemon.
//!
//! Implements the server side of the SSH agent wire protocol on top of
//! [`ssh_agent_lib`]. Keys are held in-memory only, wrapped in types that
//! zeroize on drop; nothing is ever persisted to disk. `SIGTERM` and
//! `SIGINT` trigger graceful shutdown — the socket is unlinked, the pid
//! file removed, and every stored key is zeroed before the process exits.
//!
//! # Signing support
//!
//! The daemon accepts `Add` for keys of every algorithm Gitway's
//! `keygen` can produce (Ed25519, ECDSA P-256/384/521, RSA 2048..16384).
//! The `Sign` handler covers **Ed25519 and all three ECDSA curves** via
//! `ssh-key`'s built-in `Signer<Signature>` trait; RSA sign is still
//! stubbed because the agent wire protocol's `SignRequest.flags` picks
//! between SHA-256 and SHA-512 at call time, and the generic trait impl
//! has no way to honor that. RSA support lands in a follow-up that
//! routes through `rsa::pkcs1v15::SigningKey<Sha…>` directly.
//!
//! # Example
//!
//! ```no_run
//! use std::path::PathBuf;
//! use gitway_lib::agent::daemon::{AgentDaemonConfig, run};
//!
//! # async fn doc() -> Result<(), gitway_lib::GitwayError> {
//! let cfg = AgentDaemonConfig {
//!     socket_path: PathBuf::from("/tmp/gitway-agent.sock"),
//!     pid_file: None,
//!     default_ttl: None,
//! };
//! run(cfg).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ssh_agent_lib::agent::{listen, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{
    AddIdentity, AddIdentityConstrained, Credential, Identity, KeyConstraint, RemoveIdentity,
    SignRequest,
};
use ssh_key::{HashAlg, PrivateKey, Signature};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

use crate::GitwayError;

// ── Public types ──────────────────────────────────────────────────────────────

/// Configuration for [`run`].
///
/// `socket_path` must be on a filesystem that supports Unix domain sockets
/// (`$XDG_RUNTIME_DIR` is conventional). The directory permissions are the
/// caller's responsibility; the daemon will set the socket inode to 0600.
#[derive(Debug, Clone)]
pub struct AgentDaemonConfig {
    /// Path to bind the agent socket on.
    pub socket_path: PathBuf,
    /// Optional pid-file location. If `Some`, the daemon writes its PID
    /// here on startup and removes the file on shutdown.
    pub pid_file: Option<PathBuf>,
    /// Default lifetime applied to added keys when the client does not
    /// specify one via `KeyConstraint::Lifetime`.
    pub default_ttl: Option<Duration>,
}

// ── Internal state ────────────────────────────────────────────────────────────

/// One key loaded into the daemon.
///
/// `PrivateKey` already zeroizes on drop (via its inner `KeypairData`).
/// The struct only adds user-visible metadata — no additional secret
/// material to worry about.
#[derive(Debug, Clone)]
struct StoredKey {
    key: PrivateKey,
    expires_at: Option<Instant>,
    confirm: bool,
}

/// Daemon-wide key store + lock state, shared across connections.
#[derive(Debug, Default)]
struct KeyStore {
    /// Keyed by SHA-256 fingerprint of the public key so remove-by-pubkey
    /// is O(1).
    keys: HashMap<String, StoredKey>,
    /// Agent-wide lock state (`ssh-add -x`). When `Some`, all Session
    /// methods that would return secret material or alter the store
    /// error with `AgentError::Failure` until `unlock` is called with
    /// the same passphrase.
    lock: Option<String>,
}

impl KeyStore {
    fn new() -> Self {
        Self::default()
    }

    /// Returns `true` while the agent is locked.
    fn is_locked(&self) -> bool {
        self.lock.is_some()
    }

    /// Removes every key whose `expires_at` is in the past.
    ///
    /// Called from the TTL sweeper task every second.
    fn evict_expired(&mut self, now: Instant) {
        self.keys.retain(|_fp, k| match k.expires_at {
            Some(t) => t > now,
            None => true,
        });
    }
}

// ── Session impl ──────────────────────────────────────────────────────────────

/// Per-connection session. Cloned by `ssh-agent-lib`'s accept loop; all
/// state lives behind the shared `Arc<Mutex<KeyStore>>`.
#[derive(Debug, Clone)]
struct AgentSession {
    store: Arc<Mutex<KeyStore>>,
    default_ttl: Option<Duration>,
}

#[async_trait]
impl Session for AgentSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let store = self.store.lock().await;
        if store.is_locked() {
            return Err(AgentError::Failure);
        }
        Ok(store
            .keys
            .values()
            .map(|s| Identity {
                pubkey: s.key.public_key().key_data().clone(),
                comment: s.key.comment().to_owned(),
            })
            .collect())
    }

    async fn add_identity(&mut self, req: AddIdentity) -> Result<(), AgentError> {
        self.add_inner(req, Vec::new()).await
    }

    async fn add_identity_constrained(
        &mut self,
        req: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        self.add_inner(req.identity, req.constraints).await
    }

    async fn remove_identity(&mut self, req: RemoveIdentity) -> Result<(), AgentError> {
        let mut store = self.store.lock().await;
        if store.is_locked() {
            return Err(AgentError::Failure);
        }
        let pk = ssh_key::PublicKey::from(req.pubkey);
        let fp = pk.fingerprint(HashAlg::Sha256).to_string();
        if store.keys.remove(&fp).is_none() {
            return Err(AgentError::Failure);
        }
        Ok(())
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        let mut store = self.store.lock().await;
        if store.is_locked() {
            return Err(AgentError::Failure);
        }
        store.keys.clear();
        Ok(())
    }

    async fn sign(&mut self, req: SignRequest) -> Result<Signature, AgentError> {
        let store = self.store.lock().await;
        if store.is_locked() {
            return Err(AgentError::Failure);
        }
        let pk = ssh_key::PublicKey::from(req.pubkey.clone());
        let fp = pk.fingerprint(HashAlg::Sha256).to_string();
        let stored = store.keys.get(&fp).ok_or(AgentError::Failure)?;

        if stored.confirm {
            // v0.6 does not implement interactive confirmation — the
            // daemon would need a side-channel to the user. Reject
            // rather than sign silently.
            log::warn!(
                "gitway-agent: sign request for confirm-required key {fp} rejected — \
                 interactive confirmation not yet implemented"
            );
            return Err(AgentError::Failure);
        }

        sign_with_key(&stored.key, &req.data).map_err(|e| {
            log::warn!("gitway-agent: sign failed for {fp}: {e}");
            AgentError::Failure
        })
    }

    async fn lock(&mut self, key: String) -> Result<(), AgentError> {
        let mut store = self.store.lock().await;
        if store.is_locked() {
            return Err(AgentError::Failure);
        }
        store.lock = Some(key);
        Ok(())
    }

    async fn unlock(&mut self, key: String) -> Result<(), AgentError> {
        let mut store = self.store.lock().await;
        match &store.lock {
            Some(current) if *current == key => {
                store.lock = None;
                Ok(())
            }
            _ => Err(AgentError::Failure),
        }
    }
}

impl AgentSession {
    async fn add_inner(
        &mut self,
        req: AddIdentity,
        constraints: Vec<KeyConstraint>,
    ) -> Result<(), AgentError> {
        let mut store = self.store.lock().await;
        if store.is_locked() {
            return Err(AgentError::Failure);
        }

        let key = match req.credential {
            Credential::Key { privkey, comment } => {
                let mut pk = PrivateKey::try_from(privkey).map_err(|e| {
                    log::warn!("gitway-agent: add failed to parse credential: {e}");
                    AgentError::Failure
                })?;
                pk.set_comment(&comment);
                pk
            }
            Credential::Cert { .. } => {
                // Certificate-bound keys would need cert validation we
                // have not wired up. Reject politely.
                return Err(AgentError::Failure);
            }
        };

        let mut expires_at = self.default_ttl.map(|d| Instant::now() + d);
        let mut confirm = false;
        for c in constraints {
            match c {
                KeyConstraint::Lifetime(secs) => {
                    expires_at = Some(Instant::now() + Duration::from_secs(u64::from(secs)));
                }
                KeyConstraint::Confirm => {
                    confirm = true;
                }
                KeyConstraint::Extension(_) => {
                    // Silently ignore unknown extension-based constraints.
                }
            }
        }

        let fp = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        store.keys.insert(
            fp,
            StoredKey {
                key,
                expires_at,
                confirm,
            },
        );
        Ok(())
    }
}

// ── Signing ───────────────────────────────────────────────────────────────────

/// Signs `data` with `key`.
///
/// Ed25519 and all three ECDSA curves (NIST P-256, P-384, P-521) use
/// `ssh-key`'s built-in `Signer<Signature>` impl, which picks the right
/// inner crypto crate (`ed25519-dalek`, `p256`, `p384`, `p521`) and
/// emits the SSH wire format the agent protocol expects.
///
/// RSA signing still returns [`GitwayError::invalid_config`] because
/// the agent protocol's `SignRequest.flags` picks between SHA-256 and
/// SHA-512 at call time, and ssh-key's blanket Signer impl has no way
/// to honor that. Implementing RSA here needs a separate path that
/// reads the flag and routes through `rsa::pkcs1v15::SigningKey<Sha…>`
/// directly — tracked as a v0.6.x follow-up.
fn sign_with_key(key: &PrivateKey, data: &[u8]) -> Result<Signature, GitwayError> {
    use signature::Signer;
    use ssh_key::Algorithm;
    match key.algorithm() {
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } => key
            .try_sign(data)
            .map_err(|e| GitwayError::signing(format!("sign failed: {e}"))),
        other => Err(GitwayError::invalid_config(format!(
            "agent daemon sign: algorithm {} not yet supported \
             (Ed25519 + ECDSA P-256/P-384/P-521 in v0.6; RSA follows in v0.6.x)",
            other.as_str()
        ))),
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Runs the agent daemon until a termination signal arrives.
///
/// # Errors
///
/// Returns [`GitwayError`] if the socket cannot be bound, the pid file
/// cannot be written, or the accept loop returns with an error.
///
/// # Termination
///
/// On `SIGTERM` or `SIGINT` the function returns `Ok(())` after unlinking
/// the socket and removing the pid file. Every stored key is zeroed as
/// the `KeyStore` drops.
pub async fn run(config: AgentDaemonConfig) -> Result<(), GitwayError> {
    let listener = bind_unix_socket(&config.socket_path)?;
    write_pid_file(config.pid_file.as_deref())?;

    let store = Arc::new(Mutex::new(KeyStore::new()));
    let session = AgentSession {
        store: Arc::clone(&store),
        default_ttl: config.default_ttl,
    };

    // Background task: evict expired keys once per second.
    let evict_store = Arc::clone(&store);
    let evict_handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let now = Instant::now();
            let mut s = evict_store.lock().await;
            s.evict_expired(now);
        }
    });

    // Accept loop + shutdown race. `listen` runs until the listener errors
    // out; we race it against SIGTERM/SIGINT so a signal always wins.
    let shutdown = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let sigterm = async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        term.recv().await;
        Ok::<_, std::io::Error>(())
    };

    let accept_loop = listen(listener, session);

    tokio::select! {
        res = accept_loop => {
            if let Err(e) = res {
                log::warn!("gitway-agent: accept loop ended with error: {e}");
            }
        }
        _ = shutdown => {
            log::info!("gitway-agent: SIGINT received, shutting down");
        }
        _ = sigterm => {
            log::info!("gitway-agent: SIGTERM received, shutting down");
        }
    }

    evict_handle.abort();
    cleanup(&config);
    Ok(())
}

// ── Socket / pid plumbing ─────────────────────────────────────────────────────

fn bind_unix_socket(path: &Path) -> Result<UnixListener, GitwayError> {
    use std::os::unix::fs::PermissionsExt as _;
    // Remove any stale socket file so bind() doesn't fail with "address in use".
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    // Restrict the socket inode to the owning user only.
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(SOCKET_MODE);
    std::fs::set_permissions(path, perms)?;
    Ok(listener)
}

fn write_pid_file(path: Option<&Path>) -> Result<(), GitwayError> {
    let Some(p) = path else {
        return Ok(());
    };
    let pid = std::process::id();
    std::fs::write(p, format!("{pid}\n"))?;
    Ok(())
}

fn cleanup(config: &AgentDaemonConfig) {
    let _ = std::fs::remove_file(&config.socket_path);
    if let Some(ref p) = config.pid_file {
        let _ = std::fs::remove_file(p);
    }
}

/// Unix-mode bits for the agent socket (owner read/write only).
const SOCKET_MODE: u32 = 0o600;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{generate, KeyType};

    #[test]
    fn evict_expired_drops_past_keys_only() {
        let key_now = generate(KeyType::Ed25519, None, "now").unwrap();
        let key_later = generate(KeyType::Ed25519, None, "later").unwrap();
        let fp_now = key_now
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        let fp_later = key_later
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        let mut store = KeyStore::new();
        // Use checked_sub so clippy's unchecked-duration-subtraction lint
        // is happy even though we know the test runs after process start.
        let past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("test runs after process start; Instant never underflows");
        store.keys.insert(
            fp_now.clone(),
            StoredKey {
                key: key_now,
                expires_at: Some(past),
                confirm: false,
            },
        );
        store.keys.insert(
            fp_later.clone(),
            StoredKey {
                key: key_later,
                expires_at: Some(Instant::now() + Duration::from_secs(60)),
                confirm: false,
            },
        );
        store.evict_expired(Instant::now());
        assert!(!store.keys.contains_key(&fp_now));
        assert!(store.keys.contains_key(&fp_later));
    }

    #[test]
    fn sign_ed25519_roundtrip_verifies_with_public_key() {
        use ed25519_dalek::Verifier as _;
        let key = generate(KeyType::Ed25519, None, "roundtrip").unwrap();
        let data = b"hello gitway agent";
        let sig = sign_with_key(&key, data).unwrap();
        assert_eq!(sig.algorithm(), ssh_key::Algorithm::Ed25519);

        // Cross-verify via ed25519-dalek directly.
        let ssh_key::public::KeyData::Ed25519(pk) = key.public_key().key_data() else {
            unreachable!()
        };
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&pk.0).unwrap();
        let bytes: [u8; 64] = sig.as_bytes().try_into().unwrap();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&bytes);
        verifying.verify(data, &dalek_sig).unwrap();
    }

    /// Verifies that `sign_with_key` produces a signature that
    /// `ssh_key::PublicKey::verify` (which delegates to the underlying
    /// `RustCrypto` verifier for this algorithm) accepts. Parameterised
    /// over `KeyType` so one helper covers Ed25519 + the three ECDSA
    /// curves.
    fn sign_verify_roundtrip(kind: KeyType) {
        use signature::Verifier;
        let key = generate(kind, None, "roundtrip").unwrap();
        let data = b"hello gitway agent";
        let sig = sign_with_key(&key, data).unwrap();
        key.public_key()
            .key_data()
            .verify(data, &sig)
            .unwrap_or_else(|e| panic!("verify failed for {kind:?}: {e}"));
    }

    #[test]
    fn sign_ecdsa_p256_roundtrip() {
        sign_verify_roundtrip(KeyType::EcdsaP256);
    }

    #[test]
    fn sign_ecdsa_p384_roundtrip() {
        sign_verify_roundtrip(KeyType::EcdsaP384);
    }

    #[test]
    fn sign_ecdsa_p521_roundtrip() {
        sign_verify_roundtrip(KeyType::EcdsaP521);
    }

    #[test]
    fn sign_rsa_is_not_supported_yet() {
        let key = generate(KeyType::Rsa, Some(2048), "rsa-nope").unwrap();
        let err = sign_with_key(&key, b"data").unwrap_err();
        assert!(
            err.to_string().contains("not yet supported"),
            "unexpected error: {err}"
        );
    }
}
