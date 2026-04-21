// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Interactive confirmation prompts for the SSH agent daemon.
//!
//! When a key was added with `--confirm` (SSH agent protocol's
//! `SSH_AGENT_CONSTRAIN_CONFIRM`), the daemon must ask the user before
//! each sign request. OpenSSH handles this by invoking the program
//! named in `$SSH_ASKPASS` with `SSH_ASKPASS_PROMPT=confirm` in its
//! environment; that program renders a yes/no dialog and signals the
//! user's choice through its exit status — `0` means approved,
//! anything else means denied.
//!
//! This module mirrors that contract. It is the server-side companion
//! to `try_askpass` in `gitway-cli/src/main.rs`, which does the
//! client-side passphrase flow. Same security invariants apply:
//!
//! * `SSH_ASKPASS` must be an absolute path — a relative value could
//!   be resolved via `PATH` to a binary the user did not intend to
//!   run.
//! * The file must not be world-writable on Unix — any local user
//!   could otherwise overwrite it between the check and `execve(2)`
//!   to spy on sign prompts.
//! * Askpass invocations run with a hard timeout so a wedged dialog
//!   cannot pin the `Session` lock indefinitely.
//!
//! The [`confirm`] entry point is fail-safe: any error (missing
//! askpass, security violation, spawn failure, timeout) resolves to a
//! denial, which the daemon then translates into `AgentError::Failure`
//! back to the client.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

use crate::GitwayError;

/// Hard cap for how long the daemon will wait on an askpass reply.
///
/// Long enough for a user to notice the dialog, walk to the keyboard,
/// and click a button; short enough that a wedged askpass (frozen
/// GUI, disconnected display) cannot hold the keystore lock forever.
/// OpenSSH has no equivalent cap — `ssh_askpass` blocks until the
/// child process exits — but our daemon cooperatively serves other
/// clients in the meantime, so bounding the wait matters here.
const ASKPASS_TIMEOUT: Duration = Duration::from_secs(60);

/// Prompts the user to approve a sign request. Returns `true` when
/// the askpass program exits `0`, `false` in every other case.
///
/// The outcome is logged at info level on denial and warn level on
/// internal error, so operators running the daemon under systemd or
/// a log aggregator can tell "user said no" apart from "askpass is
/// misconfigured".
///
/// # Environment
///
/// Reads `SSH_ASKPASS` — if unset, returns `false` after logging a
/// warning. Writes `SSH_ASKPASS_PROMPT=confirm` into the child's
/// environment so the askpass program renders a yes/no dialog rather
/// than a passphrase field.
pub async fn confirm(prompt: &str) -> bool {
    let Some(askpass_raw) = std::env::var_os("SSH_ASKPASS") else {
        log::warn!(
            "gitway-agent: sign request for confirm-required key rejected — \
             SSH_ASKPASS is not set"
        );
        return false;
    };
    match confirm_with(&askpass_raw, prompt).await {
        Ok(true) => true,
        Ok(false) => {
            log::info!("gitway-agent: user denied sign request via askpass");
            false
        }
        Err(e) => {
            log::warn!("gitway-agent: askpass confirm failed: {e}");
            false
        }
    }
}

/// Spawns `askpass` with the given prompt and returns whether it
/// exited `0`. Exposed as a separate function so tests can drive the
/// confirmation path with a known-good script without having to mutate
/// the process environment.
///
/// # Errors
///
/// Returns [`GitwayError`] when the path fails security validation
/// (not absolute, world-writable), the spawn itself fails, or the
/// child does not exit within [`ASKPASS_TIMEOUT`].
pub async fn confirm_with(askpass: &OsString, prompt: &str) -> Result<bool, GitwayError> {
    let path = PathBuf::from(askpass);
    validate_security(&path)?;

    let mut cmd = Command::new(&path);
    cmd.arg(prompt)
        .env("SSH_ASKPASS_PROMPT", "confirm")
        .stdin(std::process::Stdio::null())
        // Askpass implementations commonly print nothing on stdout for
        // confirm-mode calls; we do not read it either way. Silence
        // both streams so a chatty askpass cannot leak prompts into
        // whatever log sink the daemon's stderr is pointed at.
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    let status = match timeout(ASKPASS_TIMEOUT, cmd.status()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(GitwayError::signing(format!(
                "askpass spawn failed for {}: {e}",
                path.display()
            )));
        }
        Err(_elapsed) => {
            return Err(GitwayError::signing(format!(
                "askpass {} did not respond within {:?}",
                path.display(),
                ASKPASS_TIMEOUT
            )));
        }
    };

    Ok(status.success())
}

/// Rejects askpass paths that are unsafe to `execve` — relative paths
/// (PATH injection) and world-writable files (local tampering). Both
/// checks mirror the client-side `try_askpass` so operators only need
/// to learn the rules once.
fn validate_security(askpass: &Path) -> Result<(), GitwayError> {
    if !askpass.is_absolute() {
        return Err(GitwayError::invalid_config(format!(
            "SSH_ASKPASS {} must be an absolute path",
            askpass.display()
        )));
    }
    let meta = std::fs::metadata(askpass).map_err(|e| {
        GitwayError::invalid_config(format!(
            "SSH_ASKPASS {} cannot be stat()ed: {e}",
            askpass.display()
        ))
    })?;
    // 0o002 is the write bit for "other". Any askpass readable to the
    // user but writable by anyone on the system is an exploit waiting
    // to happen.
    if meta.permissions().mode() & 0o002 != 0 {
        return Err(GitwayError::invalid_config(format!(
            "SSH_ASKPASS {} is world-writable and cannot be trusted",
            askpass.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Builds an executable shell script under `dir` that simply
    /// `exit`s with the given status, and returns its path.
    fn fixture(dir: &TempDir, name: &str, exit_code: i32) -> OsString {
        let path = dir.path().join(name);
        fs::write(&path, format!("#!/bin/sh\nexit {exit_code}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.into_os_string()
    }

    #[tokio::test]
    async fn approves_when_askpass_exits_zero() {
        let dir = TempDir::new().unwrap();
        let yes = fixture(&dir, "yes", 0);
        let approved = confirm_with(&yes, "allow?").await.unwrap();
        assert!(approved);
    }

    #[tokio::test]
    async fn denies_when_askpass_exits_nonzero() {
        let dir = TempDir::new().unwrap();
        let no = fixture(&dir, "no", 1);
        let approved = confirm_with(&no, "allow?").await.unwrap();
        assert!(!approved);
    }

    #[tokio::test]
    async fn rejects_relative_path() {
        let raw = OsString::from("relative-askpass.sh");
        let err = confirm_with(&raw, "allow?").await.unwrap_err();
        assert!(
            err.to_string().contains("absolute"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_world_writable_askpass() {
        let dir = TempDir::new().unwrap();
        let yes = fixture(&dir, "leaky", 0);
        fs::set_permissions(Path::new(&yes), fs::Permissions::from_mode(0o757)).unwrap();
        let err = confirm_with(&yes, "allow?").await.unwrap_err();
        assert!(
            err.to_string().contains("world-writable"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn reports_missing_askpass() {
        let raw = OsString::from("/definitely/does/not/exist/askpass.sh");
        let err = confirm_with(&raw, "allow?").await.unwrap_err();
        // Either `stat()ed` (our wrapper) or a downstream OS-level
        // error message; both are acceptable.
        let msg = err.to_string();
        assert!(
            msg.contains("stat()ed") || msg.contains("No such"),
            "unexpected error: {msg}"
        );
    }
}
