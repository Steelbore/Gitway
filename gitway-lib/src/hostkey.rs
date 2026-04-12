// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! GitHub host-key fingerprint pinning (FR-6, FR-7).
//!
//! Gitssh embeds GitHub's published SHA-256 fingerprints for all three key
//! types. On every connection the server's presented key is hashed and the
//! resulting fingerprint is compared against this list. Any mismatch aborts
//! the connection immediately.
//!
//! # GitHub Enterprise Server
//!
//! Custom GHE fingerprints can be added via a `known_hosts`-style file at
//! `~/.config/gitssh/known_hosts` (FR-7). Each non-comment line must follow
//! the format:
//!
//! ```text
//! hostname SHA256:<base64-encoded-fingerprint>
//! ```
//!
//! # Fingerprint source
//!
//! <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints>
//!
//! Last verified: 2026-04-05

use std::path::Path;

use crate::error::{GitsshError, GitsshErrorKind};

// ── Well-known constants ──────────────────────────────────────────────────────

/// Primary GitHub SSH host (FR-1).
pub const DEFAULT_GITHUB_HOST: &str = "github.com";

/// Primary port for GitHub SSH connections (FR-1).
///
/// Changing to a value below 1024 requires elevated privileges on most
/// POSIX systems; only override this when using GHE with a non-standard port.
pub const DEFAULT_PORT: u16 = 22;

/// Fallback host when port 22 is unavailable (FR-1).
///
/// GitHub routes SSH traffic through HTTPS port 443 on this hostname.
pub const FALLBACK_HOST: &str = "ssh.github.com";

/// Fallback port for GitHub SSH connections (FR-1).
pub const FALLBACK_PORT: u16 = 443;

/// GitHub's published SSH host-key fingerprints (SHA-256, FR-6).
///
/// Contains one entry per key type in `SHA256:<base64>` format:
/// - Ed25519  (index 0)
/// - ECDSA    (index 1)
/// - RSA      (index 2)
///
/// **If GitHub rotates its keys, update this constant and cut a patch release.**
/// The `--insecure-skip-host-check` flag (FR-8) bypasses this check.
pub const GITHUB_FINGERPRINTS: &[&str] = &[
    "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", // Ed25519
    "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM", // ECDSA-SHA2-nistp256
    "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s", // RSA
];

// ── Known-hosts parser for GHE support ───────────────────────────────────────

/// Parses a GHE known-hosts file and returns all fingerprints for `hostname`.
///
/// Lines starting with `#` and blank lines are ignored. Each valid line has
/// the form `hostname SHA256:<fp>`.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
fn fingerprints_from_known_hosts(
    path: &Path,
    hostname: &str,
) -> Result<Vec<String>, GitsshError> {
    let content = std::fs::read_to_string(path)?;
    let mut fps = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        let Some(host_part) = parts.next() else {
            continue;
        };
        let Some(fp_part) = parts.next() else {
            continue;
        };
        if host_part == hostname {
            fps.push(fp_part.trim().to_owned());
        }
    }

    Ok(fps)
}

/// Returns the default GHE known-hosts path: `~/.config/gitssh/known_hosts`.
fn default_known_hosts_path() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|d| d.join("gitssh").join("known_hosts"))
}

// ── Public verifier ───────────────────────────────────────────────────────────

/// Collects all expected fingerprints for `host`.
///
/// For `github.com` (and `ssh.github.com`) this is the embedded set. For any
/// other host the custom known-hosts file is consulted first; if the file
/// provides entries those are used, otherwise the embedded set is returned as
/// a fallback for sub-domains / mirrors.
///
/// # Errors
///
/// Returns an error if `custom_path` is specified but cannot be read.
pub fn fingerprints_for_host(
    host: &str,
    custom_path: &Option<std::path::PathBuf>,
) -> Result<Vec<String>, GitsshError> {
    let is_github = matches!(host, "github.com" | "ssh.github.com");

    // For canonical GitHub hosts start with the embedded set.
    let mut fps: Vec<String> = if is_github {
        GITHUB_FINGERPRINTS.iter().map(|&s| s.to_owned()).collect()
    } else {
        Vec::new()
    };

    // Consult the GHE file (user-supplied path or the default location).
    let known_hosts_path = custom_path
        .clone()
        .or_else(default_known_hosts_path);

    if let Some(ref path) = known_hosts_path {
        if path.exists() {
            let extras = fingerprints_from_known_hosts(path, host)?;
            fps.extend(extras);
        }
    }

    // Non-GitHub host with no known-hosts entries → configuration problem.
    if fps.is_empty() {
        return Err(GitsshError::new(GitsshErrorKind::InvalidConfig {
            message: format!(
                "no fingerprints found for host '{host}'; \
                 add an entry to ~/.config/gitssh/known_hosts"
            ),
        }));
    }

    Ok(fps)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_com_returns_three_fingerprints() {
        let fps = fingerprints_for_host("github.com", &None).unwrap();
        assert_eq!(fps.len(), 3);
    }

    #[test]
    fn ssh_github_com_returns_same_fingerprints() {
        let fps = fingerprints_for_host("ssh.github.com", &None).unwrap();
        assert_eq!(fps.len(), 3);
    }

    #[test]
    fn all_fingerprints_start_with_sha256_prefix() {
        for fp in GITHUB_FINGERPRINTS {
            assert!(fp.starts_with("SHA256:"), "malformed fingerprint: {fp}");
        }
    }

    #[test]
    fn unknown_host_without_known_hosts_is_error() {
        let result = fingerprints_for_host("ghe.example.com", &None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("ghe.example.com"));
    }
}
