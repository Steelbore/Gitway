// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! SSH host-key fingerprint pinning for well-known Git hosting services (FR-6, FR-7).
//!
//! Gitssh embeds the published SHA-256 fingerprints for GitHub, GitLab, and
//! Codeberg.  On every connection the server's presented key is hashed and the
//! resulting fingerprint is compared against the embedded list for that host.
//! Any mismatch aborts the connection immediately.
//!
//! # Custom / self-hosted instances
//!
//! Fingerprints for any host not listed below can be added via a
//! `known_hosts`-style file at `~/.config/gitway/known_hosts` (FR-7).
//! Each non-comment line must follow the format:
//!
//! ```text
//! hostname SHA256:<base64-encoded-fingerprint>
//! ```
//!
//! # Fingerprint sources
//!
//! - GitHub:   <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints>
//! - GitLab:   <https://docs.gitlab.com/ee/user/gitlab_com/index.html#ssh-host-keys-fingerprints>
//! - Codeberg: <https://docs.codeberg.org/security/ssh-fingerprint/>
//!
//! Last verified: 2026-04-11

use std::path::Path;

use crate::error::{GitwayError, GitwayErrorKind};

// ── Well-known host constants ─────────────────────────────────────────────────

/// Primary GitHub SSH host (FR-1).
pub const DEFAULT_GITHUB_HOST: &str = "github.com";

/// Fallback GitHub SSH host when port 22 is unavailable (FR-1).
///
/// GitHub routes SSH traffic through HTTPS port 443 on this hostname.
pub const GITHUB_FALLBACK_HOST: &str = "ssh.github.com";

/// Primary GitLab SSH host.
pub const DEFAULT_GITLAB_HOST: &str = "gitlab.com";

/// Fallback GitLab SSH host when port 22 is unavailable.
///
/// GitLab routes SSH traffic through HTTPS port 443 on this hostname.
pub const GITLAB_FALLBACK_HOST: &str = "altssh.gitlab.com";

/// Primary Codeberg SSH host.
pub const DEFAULT_CODEBERG_HOST: &str = "codeberg.org";

/// Default SSH port used by all providers.
///
/// Changing to a value below 1024 requires elevated privileges on most
/// POSIX systems; only override this when using a self-hosted instance
/// with a non-standard port.
pub const DEFAULT_PORT: u16 = 22;

/// HTTPS-port fallback for providers that support it (GitHub, GitLab).
pub const FALLBACK_PORT: u16 = 443;

// ── Legacy alias kept for backward compatibility ──────────────────────────────

/// Alias for [`GITHUB_FALLBACK_HOST`]; retained so existing callers that
/// reference the old name continue to compile.
#[deprecated(since = "0.2.0", note = "use GITHUB_FALLBACK_HOST instead")]
pub const FALLBACK_HOST: &str = GITHUB_FALLBACK_HOST;

// ── Embedded fingerprints ─────────────────────────────────────────────────────

/// GitHub's published SSH host-key fingerprints (SHA-256, FR-6).
///
/// Contains one entry per key type in `SHA256:<base64>` format:
/// - Ed25519  (index 0)
/// - ECDSA    (index 1)
/// - RSA      (index 2)
///
/// **If GitHub rotates its keys, update this constant and cut a patch release.**
pub const GITHUB_FINGERPRINTS: &[&str] = &[
    "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", // Ed25519
    "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM", // ECDSA-SHA2-nistp256
    "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s", // RSA
];

/// GitLab.com's published SSH host-key fingerprints (SHA-256).
///
/// Contains one entry per key type in `SHA256:<base64>` format:
/// - Ed25519  (index 0)
/// - ECDSA    (index 1)
/// - RSA      (index 2)
///
/// **If GitLab rotates its keys, update this constant and cut a patch release.**
pub const GITLAB_FINGERPRINTS: &[&str] = &[
    "SHA256:eUXGGm1YGsMAS7vkcx6JOJdOGHPem5gQp4taiCfCLB8", // Ed25519
    "SHA256:HbW3g8zUjNSksFbqTiUWPWg2Bq1x8xdGUrliXFzSnUw", // ECDSA-SHA2-nistp256
    "SHA256:ROQFvPThGrW4RuWLoL9tq9I9zJ42fK4XywyRtbOz/EQ",  // RSA
];

/// Codeberg.org's published SSH host-key fingerprints (SHA-256).
///
/// Contains one entry per key type in `SHA256:<base64>` format:
/// - Ed25519  (index 0)
/// - ECDSA    (index 1)
/// - RSA      (index 2)
///
/// **If Codeberg rotates its keys, update this constant and cut a patch release.**
pub const CODEBERG_FINGERPRINTS: &[&str] = &[
    "SHA256:mIlxA9k46MmM6qdJOdMnAQpzGxF4WIVVL+fj+wZbw0g", // Ed25519
    "SHA256:T9FYDEHELhVkulEKKwge5aVhVTbqCW0MIRwAfpARs/E",  // ECDSA-SHA2-nistp256
    "SHA256:6QQmYi4ppFS4/+zSZ5S4IU+4sa6rwvQ4PbhCtPEBekQ",  // RSA
];

// ── Known-hosts parser for custom / GHE support ───────────────────────────────

/// Parses a known-hosts file and returns all fingerprints for `hostname`.
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
) -> Result<Vec<String>, GitwayError> {
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

/// Returns the default known-hosts path: `~/.config/gitway/known_hosts`.
fn default_known_hosts_path() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|d| d.join("gitway").join("known_hosts"))
}

// ── Public verifier ───────────────────────────────────────────────────────────

/// Collects all expected fingerprints for `host`.
///
/// For well-known hosts (GitHub, GitLab, Codeberg and their fallback
/// hostnames) the embedded fingerprint set is returned.  For any other host
/// the custom known-hosts file is consulted; if it provides entries those are
/// used, otherwise the connection is refused with an actionable error.
///
/// # Errors
///
/// Returns an error if `custom_path` is specified but cannot be read, or if
/// no fingerprints can be found for the given host.
pub fn fingerprints_for_host(
    host: &str,
    custom_path: &Option<std::path::PathBuf>,
) -> Result<Vec<String>, GitwayError> {
    // Start with the embedded set for the well-known hosted services.
    let mut fps: Vec<String> = match host {
        "github.com" | "ssh.github.com" => {
            GITHUB_FINGERPRINTS.iter().map(|&s| s.to_owned()).collect()
        }
        "gitlab.com" | "altssh.gitlab.com" => {
            GITLAB_FINGERPRINTS.iter().map(|&s| s.to_owned()).collect()
        }
        "codeberg.org" => {
            CODEBERG_FINGERPRINTS.iter().map(|&s| s.to_owned()).collect()
        }
        _ => Vec::new(),
    };

    // Consult the known-hosts file (user-supplied path or the default location)
    // to allow custom / self-hosted instances and to let users extend or
    // override the embedded sets.
    let known_hosts_path = custom_path.clone().or_else(default_known_hosts_path);

    if let Some(ref path) = known_hosts_path {
        if path.exists() {
            let extras = fingerprints_from_known_hosts(path, host)?;
            fps.extend(extras);
        }
    }

    // No fingerprints at all → refuse the connection with a clear message.
    if fps.is_empty() {
        return Err(GitwayError::new(GitwayErrorKind::InvalidConfig {
            message: format!(
                "no fingerprints found for host '{host}'; \
                 add an entry to ~/.config/gitway/known_hosts"
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
    fn gitlab_com_returns_three_fingerprints() {
        let fps = fingerprints_for_host("gitlab.com", &None).unwrap();
        assert_eq!(fps.len(), 3);
    }

    #[test]
    fn altssh_gitlab_com_returns_same_fingerprints_as_gitlab() {
        let primary = fingerprints_for_host("gitlab.com", &None).unwrap();
        let fallback = fingerprints_for_host("altssh.gitlab.com", &None).unwrap();
        assert_eq!(primary, fallback);
    }

    #[test]
    fn codeberg_org_returns_three_fingerprints() {
        let fps = fingerprints_for_host("codeberg.org", &None).unwrap();
        assert_eq!(fps.len(), 3);
    }

    #[test]
    fn all_github_fingerprints_start_with_sha256_prefix() {
        for fp in GITHUB_FINGERPRINTS {
            assert!(fp.starts_with("SHA256:"), "malformed fingerprint: {fp}");
        }
    }

    #[test]
    fn all_gitlab_fingerprints_start_with_sha256_prefix() {
        for fp in GITLAB_FINGERPRINTS {
            assert!(fp.starts_with("SHA256:"), "malformed fingerprint: {fp}");
        }
    }

    #[test]
    fn all_codeberg_fingerprints_start_with_sha256_prefix() {
        for fp in CODEBERG_FINGERPRINTS {
            assert!(fp.starts_with("SHA256:"), "malformed fingerprint: {fp}");
        }
    }

    #[test]
    fn unknown_host_without_known_hosts_is_error() {
        let result = fingerprints_for_host("git.example.com", &None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("git.example.com"));
    }
}
