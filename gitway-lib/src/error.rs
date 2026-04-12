// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
// Updated 2026-04-12: added error_code(), exit_code(), hint() for SFRS Rule 2/5
//! Error types for `gitway-lib`.
//!
//! # Examples
//!
//! ```rust
//! use gitway_lib::GitwayError;
//!
//! fn handle(err: &GitwayError) {
//!     if err.is_host_key_mismatch() {
//!         eprintln!("Possible MITM — host key does not match pinned fingerprints.");
//!     }
//! }
//! ```

use std::backtrace::Backtrace;
use std::fmt;

// ── Inner error kind ──────────────────────────────────────────────────────────

/// Internal discriminant for [`GitwayError`].
///
/// Not part of the public API; callers use the `is_*` predicate methods.
#[derive(Debug)]
pub(crate) enum GitwayErrorKind {
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

impl fmt::Display for GitwayErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Ssh(e) => write!(f, "SSH protocol error: {e}"),
            Self::Keys(e) => write!(f, "SSH key error: {e}"),
            Self::HostKeyMismatch { fingerprint } => {
                write!(
                    f,
                    "host key mismatch — received fingerprint {fingerprint} \
                     does not match any pinned fingerprint"
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

/// The single error type returned by all `gitway-lib` operations.
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
/// | [`is_io`](GitwayError::is_io) | Underlying I/O failure |
/// | [`is_host_key_mismatch`](GitwayError::is_host_key_mismatch) | Server key does not match pinned fingerprints |
/// | [`is_authentication_failed`](GitwayError::is_authentication_failed) | Server rejected our key |
/// | [`is_no_key_found`](GitwayError::is_no_key_found) | No identity key available |
/// | [`is_key_encrypted`](GitwayError::is_key_encrypted) | Key file needs a passphrase |
#[derive(Debug)]
pub struct GitwayError {
    kind: GitwayErrorKind,
    backtrace: Backtrace,
}

impl GitwayError {
    /// Constructs a new [`GitwayError`] capturing the current backtrace.
    pub(crate) fn new(kind: GitwayErrorKind) -> Self {
        Self {
            kind,
            backtrace: Backtrace::capture(),
        }
    }

    // ── Constructors for common variants ─────────────────────────────────────

    pub fn host_key_mismatch(fingerprint: impl Into<String>) -> Self {
        Self::new(GitwayErrorKind::HostKeyMismatch {
            fingerprint: fingerprint.into(),
        })
    }

    #[must_use]
    pub fn authentication_failed() -> Self {
        Self::new(GitwayErrorKind::AuthenticationFailed)
    }

    #[must_use]
    pub fn no_key_found() -> Self {
        Self::new(GitwayErrorKind::NoKeyFound)
    }

    pub fn invalid_config(message: impl Into<String>) -> Self {
        Self::new(GitwayErrorKind::InvalidConfig {
            message: message.into(),
        })
    }

    // ── Predicates ────────────────────────────────────────────────────────────

    /// Returns `true` if this error originated from an I/O failure.
    #[must_use]
    pub fn is_io(&self) -> bool {
        matches!(self.kind, GitwayErrorKind::Io(_))
    }

    /// Returns `true` if the server's host key did not match any pinned fingerprint.
    #[must_use]
    pub fn is_host_key_mismatch(&self) -> bool {
        matches!(self.kind, GitwayErrorKind::HostKeyMismatch { .. })
    }

    /// Returns `true` if the server rejected our public-key authentication attempt.
    #[must_use]
    pub fn is_authentication_failed(&self) -> bool {
        matches!(self.kind, GitwayErrorKind::AuthenticationFailed)
    }

    /// Returns `true` if no usable identity key was found.
    #[must_use]
    pub fn is_no_key_found(&self) -> bool {
        matches!(self.kind, GitwayErrorKind::NoKeyFound)
    }

    /// Returns `true` if a key file was found but requires a passphrase to decrypt.
    #[must_use]
    pub fn is_key_encrypted(&self) -> bool {
        matches!(
            self.kind,
            GitwayErrorKind::Keys(russh::keys::Error::KeyIsEncrypted)
        )
    }

    /// Returns the path at which an encrypted key was found, if applicable.
    #[must_use]
    pub fn fingerprint(&self) -> Option<&str> {
        match &self.kind {
            GitwayErrorKind::HostKeyMismatch { fingerprint } => Some(fingerprint),
            _ => None,
        }
    }

    /// Returns an upper-snake-case error code for structured JSON output (SFRS Rule 5).
    ///
    /// | Code | Exit code | Condition |
    /// |------|-----------|-----------|
    /// | `GENERAL_ERROR` | 1 | I/O, SSH protocol, or key-parsing failure |
    /// | `USAGE_ERROR` | 2 | Invalid configuration or bad arguments |
    /// | `NOT_FOUND` | 3 | No identity key found |
    /// | `PERMISSION_DENIED` | 4 | Host key mismatch or authentication failure |
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match &self.kind {
            GitwayErrorKind::InvalidConfig { .. } => "USAGE_ERROR",
            GitwayErrorKind::NoKeyFound => "NOT_FOUND",
            GitwayErrorKind::HostKeyMismatch { .. } | GitwayErrorKind::AuthenticationFailed => {
                "PERMISSION_DENIED"
            }
            GitwayErrorKind::Io(_) | GitwayErrorKind::Ssh(_) | GitwayErrorKind::Keys(_) => {
                "GENERAL_ERROR"
            }
        }
    }

    /// Returns the numeric process exit code for this error (SFRS Rule 2).
    ///
    /// | Code | Meaning |
    /// |------|---------|
    /// | 1 | General / unexpected error |
    /// | 2 | Usage error (bad arguments, invalid configuration) |
    /// | 3 | Not found (no identity key, unknown host) |
    /// | 4 | Permission denied (authentication failure, host key mismatch) |
    #[must_use]
    pub fn exit_code(&self) -> u32 {
        match &self.kind {
            GitwayErrorKind::InvalidConfig { .. } => 2,
            GitwayErrorKind::NoKeyFound => 3,
            GitwayErrorKind::HostKeyMismatch { .. } | GitwayErrorKind::AuthenticationFailed => 4,
            GitwayErrorKind::Io(_) | GitwayErrorKind::Ssh(_) | GitwayErrorKind::Keys(_) => 1,
        }
    }

    /// Returns a short diagnostic hint for structured JSON output (SFRS Rule 5).
    #[must_use]
    pub fn hint(&self) -> &'static str {
        match &self.kind {
            GitwayErrorKind::HostKeyMismatch { .. } => {
                "Run 'gitway --test --verbose' to diagnose, \
                 or check ~/.config/gitway/known_hosts"
            }
            GitwayErrorKind::AuthenticationFailed => {
                "Ensure your SSH public key is registered with the Git hosting service, \
                 or run 'ssh-add' to load a key into the agent"
            }
            GitwayErrorKind::NoKeyFound => {
                "Run 'ssh-keygen -t ed25519' to generate a key, or use --identity to specify one"
            }
            GitwayErrorKind::InvalidConfig { .. } => {
                "Run 'gitway --help' for usage information"
            }
            GitwayErrorKind::Io(_) | GitwayErrorKind::Ssh(_) | GitwayErrorKind::Keys(_) => {
                "Run 'gitway --test --verbose' to diagnose the connection"
            }
        }
    }
}

// ── Trait implementations ─────────────────────────────────────────────────────

impl fmt::Display for GitwayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        let bt = self.backtrace.to_string();
        if !bt.is_empty() && bt != "disabled backtrace" {
            write!(f, "\n\nstack backtrace:\n{bt}")?;
        }
        Ok(())
    }
}

impl std::error::Error for GitwayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            GitwayErrorKind::Io(e) => Some(e),
            GitwayErrorKind::Ssh(e) => Some(e),
            GitwayErrorKind::Keys(e) => Some(e),
            _ => None,
        }
    }

}

impl From<russh::Error> for GitwayError {
    fn from(e: russh::Error) -> Self {
        Self::new(GitwayErrorKind::Ssh(e))
    }
}

impl From<russh::keys::Error> for GitwayError {
    fn from(e: russh::keys::Error) -> Self {
        Self::new(GitwayErrorKind::Keys(e))
    }
}

impl From<std::io::Error> for GitwayError {
    fn from(e: std::io::Error) -> Self {
        Self::new(GitwayErrorKind::Io(e))
    }
}

impl From<russh::AgentAuthError> for GitwayError {
    fn from(e: russh::AgentAuthError) -> Self {
        match e {
            russh::AgentAuthError::Send(_) => Self::new(GitwayErrorKind::Ssh(russh::Error::SendError)),
            russh::AgentAuthError::Key(k) => Self::new(GitwayErrorKind::Keys(k)),
        }
    }
}
