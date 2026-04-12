// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Error types for `gitssh-lib`.
//!
//! # Examples
//!
//! ```rust
//! use gitssh_lib::GitsshError;
//!
//! fn handle(err: &GitsshError) {
//!     if err.is_host_key_mismatch() {
//!         eprintln!("Possible MITM — host key does not match pinned fingerprints.");
//!     }
//! }
//! ```

use std::backtrace::Backtrace;
use std::fmt;

// ── Inner error kind ──────────────────────────────────────────────────────────

/// Internal discriminant for [`GitsshError`].
///
/// Not part of the public API; callers use the `is_*` predicate methods.
#[derive(Debug)]
pub(crate) enum GitsshErrorKind {
    /// Underlying I/O failure.
    Io(std::io::Error),
    /// russh protocol-level error.
    Ssh(russh::Error),
    /// russh key loading / parsing error.
    Keys(russh::keys::Error),
    /// The server's host key did not match any pinned fingerprint.
    ///
    /// `fingerprint` is the SHA-256 fingerprint that was actually received
    /// (formatted as `"SHA256:<base64>"`).
    HostKeyMismatch { fingerprint: String },
    /// Public-key authentication was rejected by the server.
    AuthenticationFailed,
    /// No usable identity key was found on any search path or agent.
    NoKeyFound,
    /// Configuration is logically invalid.
    InvalidConfig { message: String },
}

impl fmt::Display for GitsshErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Ssh(e) => write!(f, "SSH protocol error: {e}"),
            Self::Keys(e) => write!(f, "SSH key error: {e}"),
            Self::HostKeyMismatch { fingerprint } => {
                write!(
                    f,
                    "host key mismatch — received fingerprint {fingerprint} \
                     does not match any pinned GitHub fingerprint"
                )
            }
            Self::AuthenticationFailed => write!(f, "public-key authentication failed"),
            Self::NoKeyFound => {
                write!(f, "no SSH identity key found on any search path or agent")
            }
            Self::InvalidConfig { message } => write!(f, "invalid configuration: {message}"),
        }
    }
}

// ── Public error type ─────────────────────────────────────────────────────────

/// The single error type returned by all `gitssh-lib` operations.
///
/// Provides `is_*` predicate methods so callers can branch on error categories
/// without depending on internal representation. A [`Backtrace`] is captured
/// automatically; it is rendered via [`std::fmt::Display`] when
/// `RUST_BACKTRACE=1` is set.
///
/// # Predicates
///
/// | Method | Condition |
/// |---|---|
/// | [`is_io`](GitsshError::is_io) | Underlying I/O failure |
/// | [`is_host_key_mismatch`](GitsshError::is_host_key_mismatch) | Server key does not match pinned fingerprints |
/// | [`is_authentication_failed`](GitsshError::is_authentication_failed) | Server rejected our key |
/// | [`is_no_key_found`](GitsshError::is_no_key_found) | No identity key available |
/// | [`is_key_encrypted`](GitsshError::is_key_encrypted) | Key file needs a passphrase |
#[derive(Debug)]
pub struct GitsshError {
    kind: GitsshErrorKind,
    backtrace: Backtrace,
}

impl GitsshError {
    /// Constructs a new [`GitsshError`] capturing the current backtrace.
    pub(crate) fn new(kind: GitsshErrorKind) -> Self {
        Self {
            kind,
            backtrace: Backtrace::capture(),
        }
    }

    // ── Constructors for common variants ─────────────────────────────────────

    pub fn host_key_mismatch(fingerprint: impl Into<String>) -> Self {
        Self::new(GitsshErrorKind::HostKeyMismatch {
            fingerprint: fingerprint.into(),
        })
    }

    #[must_use]
    pub fn authentication_failed() -> Self {
        Self::new(GitsshErrorKind::AuthenticationFailed)
    }

    #[must_use]
    pub fn no_key_found() -> Self {
        Self::new(GitsshErrorKind::NoKeyFound)
    }

    pub fn invalid_config(message: impl Into<String>) -> Self {
        Self::new(GitsshErrorKind::InvalidConfig {
            message: message.into(),
        })
    }

    // ── Predicates ────────────────────────────────────────────────────────────

    /// Returns `true` if this error originated from an I/O failure.
    #[must_use]
    pub fn is_io(&self) -> bool {
        matches!(self.kind, GitsshErrorKind::Io(_))
    }

    /// Returns `true` if the server's host key did not match any pinned fingerprint.
    #[must_use]
    pub fn is_host_key_mismatch(&self) -> bool {
        matches!(self.kind, GitsshErrorKind::HostKeyMismatch { .. })
    }

    /// Returns `true` if the server rejected our public-key authentication attempt.
    #[must_use]
    pub fn is_authentication_failed(&self) -> bool {
        matches!(self.kind, GitsshErrorKind::AuthenticationFailed)
    }

    /// Returns `true` if no usable identity key was found.
    #[must_use]
    pub fn is_no_key_found(&self) -> bool {
        matches!(self.kind, GitsshErrorKind::NoKeyFound)
    }

    /// Returns `true` if a key file was found but requires a passphrase to decrypt.
    #[must_use]
    pub fn is_key_encrypted(&self) -> bool {
        matches!(
            self.kind,
            GitsshErrorKind::Keys(russh::keys::Error::KeyIsEncrypted)
        )
    }

    /// Returns the path at which an encrypted key was found, if applicable.
    #[must_use]
    pub fn fingerprint(&self) -> Option<&str> {
        match &self.kind {
            GitsshErrorKind::HostKeyMismatch { fingerprint } => Some(fingerprint),
            _ => None,
        }
    }
}

// ── Trait implementations ─────────────────────────────────────────────────────

impl fmt::Display for GitsshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        let bt = self.backtrace.to_string();
        if !bt.is_empty() && bt != "disabled backtrace" {
            write!(f, "\n\nstack backtrace:\n{bt}")?;
        }
        Ok(())
    }
}

impl std::error::Error for GitsshError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            GitsshErrorKind::Io(e) => Some(e),
            GitsshErrorKind::Ssh(e) => Some(e),
            GitsshErrorKind::Keys(e) => Some(e),
            _ => None,
        }
    }

}

impl From<russh::Error> for GitsshError {
    fn from(e: russh::Error) -> Self {
        Self::new(GitsshErrorKind::Ssh(e))
    }
}

impl From<russh::keys::Error> for GitsshError {
    fn from(e: russh::keys::Error) -> Self {
        Self::new(GitsshErrorKind::Keys(e))
    }
}

impl From<std::io::Error> for GitsshError {
    fn from(e: std::io::Error) -> Self {
        Self::new(GitsshErrorKind::Io(e))
    }
}

impl From<russh::AgentAuthError> for GitsshError {
    fn from(e: russh::AgentAuthError) -> Self {
        match e {
            russh::AgentAuthError::Send(_) => Self::new(GitsshErrorKind::Ssh(russh::Error::SendError)),
            russh::AgentAuthError::Key(k) => Self::new(GitsshErrorKind::Keys(k)),
        }
    }
}
