// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Configuration builder for a Gitssh session.
//!
//! # Examples
//!
//! ```rust
//! use gitssh_lib::GitsshConfig;
//! use std::time::Duration;
//!
//! let config = GitsshConfig::builder("github.com")
//!     .port(22)
//!     .username("git")
//!     .inactivity_timeout(Duration::from_secs(60))
//!     .build();
//! ```

use std::path::PathBuf;
use std::time::Duration;

use crate::hostkey::{DEFAULT_GITHUB_HOST, DEFAULT_PORT, FALLBACK_HOST, FALLBACK_PORT};

// ── Public config type ────────────────────────────────────────────────────────

/// Immutable configuration for a [`GitsshSession`](crate::GitsshSession).
///
/// Construct via [`GitsshConfig::builder`].
#[derive(Debug, Clone)]
pub struct GitsshConfig {
    /// Primary SSH host (default: `github.com`).
    pub host: String,
    /// Primary SSH port (default: 22).
    pub port: u16,
    /// Remote username (always `git` for GitHub; FR-13).
    pub username: String,
    /// Explicit identity file path supplied via `--identity`.
    pub identity_file: Option<PathBuf>,
    /// OpenSSH certificate path supplied via `--cert`.
    pub cert_file: Option<PathBuf>,
    /// When `true`, skip host-key verification (FR-8).
    pub skip_host_check: bool,
    /// Inactivity timeout for the SSH session (FR-5).
    ///
    /// GitHub's idle threshold is around 60 s; this is the configured
    /// client-side inactivity timeout, not a per-packet deadline.
    pub inactivity_timeout: Duration,
    /// Path to a `known_hosts`-style file for GitHub Enterprise Server
    /// domains (FR-7).  Format: one `hostname SHA256:<fp>` entry per line.
    pub custom_known_hosts: Option<PathBuf>,
    /// Enable verbose debug logging when `true`.
    pub verbose: bool,
    /// Optional fallback host when port 22 is unavailable (FR-1).
    ///
    /// Defaults to `ssh.github.com:443`.
    pub fallback: Option<(String, u16)>,
}

impl GitsshConfig {
    /// Begin building a config targeting `host`.
    ///
    /// All optional fields default to sensible values for GitHub.com.
    pub fn builder(host: impl Into<String>) -> GitsshConfigBuilder {
        GitsshConfigBuilder::new(host.into())
    }

    /// Convenience constructor for the default GitHub target.
    #[must_use]
    pub fn github() -> Self {
        Self::builder(DEFAULT_GITHUB_HOST).build()
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Builder for [`GitsshConfig`].
///
/// Obtained via [`GitsshConfig::builder`].
#[derive(Debug)]
#[must_use]
pub struct GitsshConfigBuilder {
    host: String,
    port: u16,
    username: String,
    identity_file: Option<PathBuf>,
    cert_file: Option<PathBuf>,
    skip_host_check: bool,
    inactivity_timeout: Duration,
    custom_known_hosts: Option<PathBuf>,
    verbose: bool,
    fallback: Option<(String, u16)>,
}

impl GitsshConfigBuilder {
    fn new(host: String) -> Self {
        Self {
            host,
            port: DEFAULT_PORT,
            username: "git".to_owned(),
            identity_file: None,
            cert_file: None,
            skip_host_check: false,
            // 60 seconds — large enough to survive slow GitHub responses.
            // Changing this below ~10 s risks spurious timeouts on congested
            // links. See GitHub's own keepalive documentation.
            inactivity_timeout: Duration::from_secs(60),
            custom_known_hosts: None,
            verbose: false,
            fallback: Some((FALLBACK_HOST.to_owned(), FALLBACK_PORT)),
        }
    }

    /// Override the target SSH port (default: 22, FR-1).
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Override the remote username (default: `"git"`, FR-13).
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    /// Set an explicit identity file path (FR-9 — highest priority).
    pub fn identity_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.identity_file = Some(path.into());
        self
    }

    /// Set an OpenSSH certificate path (FR-12).
    pub fn cert_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.cert_file = Some(path.into());
        self
    }

    /// Disable host-key verification.  **Use only for emergencies** (FR-8).
    pub fn skip_host_check(mut self, skip: bool) -> Self {
        self.skip_host_check = skip;
        self
    }

    /// Override the session inactivity timeout (FR-5).
    pub fn inactivity_timeout(mut self, timeout: Duration) -> Self {
        self.inactivity_timeout = timeout;
        self
    }

    /// Path to a custom `known_hosts`-style file for GHE domains (FR-7).
    pub fn custom_known_hosts(mut self, path: impl Into<PathBuf>) -> Self {
        self.custom_known_hosts = Some(path.into());
        self
    }

    /// Enable verbose debug logging.
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Override the fallback host/port (default: `ssh.github.com:443`, FR-1).
    /// Pass `None` to disable fallback.
    pub fn fallback(mut self, fallback: Option<(String, u16)>) -> Self {
        self.fallback = fallback;
        self
    }

    /// Finalise and return the [`GitsshConfig`].
    #[must_use]
    pub fn build(self) -> GitsshConfig {
        GitsshConfig {
            host: self.host,
            port: self.port,
            username: self.username,
            identity_file: self.identity_file,
            cert_file: self.cert_file,
            skip_host_check: self.skip_host_check,
            inactivity_timeout: self.inactivity_timeout,
            custom_known_hosts: self.custom_known_hosts,
            verbose: self.verbose,
            fallback: self.fallback,
        }
    }
}
