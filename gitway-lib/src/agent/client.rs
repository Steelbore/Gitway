// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-21
//! Blocking SSH-agent client.
//!
//! Wraps [`ssh_agent_lib::blocking::Client`] with a Gitway-native error
//! surface and a small convenience API: `connect`, `add`, `list`, `remove`,
//! `remove_all`, `lock`, `unlock`.
//!
//! The blocking API is chosen deliberately — an `ssh-add`-style binary has
//! no use for async concurrency, and avoiding tokio here keeps the
//! dependency graph small.
//!
//! # Examples
//!
//! ```no_run
//! use std::path::Path;
//! use gitway_lib::agent::client::Agent;
//!
//! let mut agent = Agent::from_env()?;
//! agent.list()?.iter().for_each(|id| println!("{}", id.fingerprint));
//! # Ok::<(), gitway_lib::GitwayError>(())
//! ```
//!
//! # Errors
//!
//! Every operation returns [`GitwayError`]. Agent-protocol failures and
//! I/O failures are both folded into the `Io` variant with a descriptive
//! message; callers that care can match via [`GitwayError::is_io`].
//!
//! # Zeroization
//!
//! `ssh-agent-lib` 0.5.2's `lock` / `unlock` take a plain `String` by
//! value, so the passphrase copy inside the library cannot be cleared on
//! our behalf. Callers supply a [`Zeroizing<String>`] and this module
//! clones only the byte contents into the library's expected `String`
//! argument; the caller's original buffer remains zeroizable.

use std::env;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use ssh_agent_lib::blocking::Client;
use ssh_agent_lib::proto::{
    AddIdentity, AddIdentityConstrained, Credential, KeyConstraint, RemoveIdentity,
};
use ssh_key::{HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use crate::GitwayError;

// ── Public types ──────────────────────────────────────────────────────────────

/// One identity loaded into the agent.
#[derive(Debug, Clone)]
pub struct Identity {
    /// The public key part, as returned by the agent.
    pub public_key: PublicKey,
    /// Comment the key was added with (often `user@host` or the file path).
    pub comment: String,
    /// `SHA256:<base64>` fingerprint — cached here to avoid recomputing.
    pub fingerprint: String,
}

/// Handle to a running SSH agent.
///
/// Thin wrapper over [`ssh_agent_lib::blocking::Client`] that translates
/// its error type into [`GitwayError`] and the protocol structs into
/// more convenient Gitway types.
#[derive(Debug)]
pub struct Agent {
    inner: Client<UnixStream>,
}

impl Agent {
    /// Connects to the agent at `$SSH_AUTH_SOCK`.
    ///
    /// # Errors
    ///
    /// Returns [`GitwayError::invalid_config`] when `$SSH_AUTH_SOCK` is
    /// unset or empty, and [`GitwayError::from`] an I/O error when the
    /// socket cannot be opened.
    pub fn from_env() -> Result<Self, GitwayError> {
        let sock = env::var("SSH_AUTH_SOCK").map_err(|_e| {
            GitwayError::invalid_config(
                "SSH_AUTH_SOCK is not set — start an agent first \
                 (e.g. `eval $(ssh-agent -s)`) or pass --socket",
            )
        })?;
        if sock.is_empty() {
            return Err(GitwayError::invalid_config("SSH_AUTH_SOCK is empty"));
        }
        Self::connect(&PathBuf::from(sock))
    }

    /// Connects to the agent socket at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`GitwayError::from`] the underlying I/O error when the
    /// socket cannot be opened.
    pub fn connect(path: &std::path::Path) -> Result<Self, GitwayError> {
        let stream = UnixStream::connect(path)?;
        Ok(Self {
            inner: Client::new(stream),
        })
    }

    /// Returns the identities currently loaded into the agent.
    ///
    /// # Errors
    ///
    /// Returns [`GitwayError`] on agent protocol or I/O failure.
    pub fn list(&mut self) -> Result<Vec<Identity>, GitwayError> {
        let raw = self
            .inner
            .request_identities()
            .map_err(|e| io_err(format!("agent list failed: {e}")))?;
        let mut out = Vec::with_capacity(raw.len());
        for id in raw {
            let public_key = PublicKey::new(id.pubkey, id.comment.clone());
            let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
            out.push(Identity {
                public_key,
                comment: id.comment,
                fingerprint,
            });
        }
        Ok(out)
    }

    /// Adds an identity to the agent.
    ///
    /// `lifetime` (if `Some`) caps how long the agent retains the key;
    /// once elapsed the agent silently evicts it — matching
    /// `ssh-add -t <seconds>`. `confirm` asks the agent to prompt the
    /// user interactively before each signing operation (agent-dependent).
    ///
    /// # Errors
    ///
    /// Returns [`GitwayError`] on agent protocol or I/O failure.
    pub fn add(
        &mut self,
        key: &PrivateKey,
        lifetime: Option<Duration>,
        confirm: bool,
    ) -> Result<(), GitwayError> {
        let identity = AddIdentity {
            credential: Credential::Key {
                privkey: key.key_data().clone(),
                comment: key.comment().to_owned(),
            },
        };
        if lifetime.is_none() && !confirm {
            self.inner
                .add_identity(identity)
                .map_err(|e| io_err(format!("agent add failed: {e}")))?;
            return Ok(());
        }
        let mut constraints: Vec<KeyConstraint> = Vec::with_capacity(2);
        if let Some(d) = lifetime {
            let secs = u32::try_from(d.as_secs())
                .map_err(|_e| GitwayError::invalid_config("lifetime exceeds u32 seconds"))?;
            constraints.push(KeyConstraint::Lifetime(secs));
        }
        if confirm {
            constraints.push(KeyConstraint::Confirm);
        }
        self.inner
            .add_identity_constrained(AddIdentityConstrained {
                identity,
                constraints,
            })
            .map_err(|e| io_err(format!("agent add (constrained) failed: {e}")))?;
        Ok(())
    }

    /// Removes a single identity from the agent.
    ///
    /// # Errors
    ///
    /// Returns [`GitwayError`] when the agent rejects the request (e.g.
    /// identity not loaded) or on I/O failure.
    pub fn remove(&mut self, public_key: &PublicKey) -> Result<(), GitwayError> {
        self.inner
            .remove_identity(RemoveIdentity {
                pubkey: public_key.key_data().clone(),
            })
            .map_err(|e| io_err(format!("agent remove failed: {e}")))
    }

    /// Removes all identities from the agent (matches `ssh-add -D`).
    ///
    /// # Errors
    ///
    /// Returns [`GitwayError`] on agent protocol or I/O failure.
    pub fn remove_all(&mut self) -> Result<(), GitwayError> {
        self.inner
            .remove_all_identities()
            .map_err(|e| io_err(format!("agent remove-all failed: {e}")))
    }

    /// Locks the agent with a passphrase (matches `ssh-add -x`).
    ///
    /// The agent refuses all signing requests until [`unlock`](Self::unlock)
    /// is called with the same passphrase.
    ///
    /// # Errors
    ///
    /// Returns [`GitwayError`] when the agent rejects the passphrase or
    /// on I/O failure. The passphrase string passed through to
    /// `ssh-agent-lib` is a fresh `String` derived from `passphrase`; the
    /// caller's [`Zeroizing`] buffer is not moved.
    pub fn lock(&mut self, passphrase: &Zeroizing<String>) -> Result<(), GitwayError> {
        self.inner
            .lock(passphrase.as_str().to_owned())
            .map_err(|e| io_err(format!("agent lock failed: {e}")))
    }

    /// Unlocks a previously-locked agent (matches `ssh-add -X`).
    ///
    /// # Errors
    ///
    /// Returns [`GitwayError`] when the agent rejects the passphrase or
    /// on I/O failure.
    pub fn unlock(&mut self, passphrase: &Zeroizing<String>) -> Result<(), GitwayError> {
        self.inner
            .unlock(passphrase.as_str().to_owned())
            .map_err(|e| io_err(format!("agent unlock failed: {e}")))
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Convert any display-able error into a `GitwayError` with an
/// `std::io::Error` source carrying `message`.
fn io_err(message: String) -> GitwayError {
    GitwayError::from(std::io::Error::other(message))
}
