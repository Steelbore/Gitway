// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Clap command-line interface definitions (FR-18, FR-19, FR-20, FR-21, FR-22).
//!
//! Invocation:
//! ```text
//! gitssh [OPTIONS] <host> <command...>
//! ```
//!
//! Unknown `-o Key=Value` OpenSSH options are silently ignored for compatibility
//! with `GIT_SSH_COMMAND` / `core.sshCommand` invocations (FR-20).

use std::path::PathBuf;

use clap::{ArgAction, Parser};

/// Gitssh — purpose-built SSH transport client for Git over GitHub.
///
/// Acts as a drop-in replacement for `ssh` when used with `GIT_SSH_COMMAND`
/// or `core.sshCommand`.  Only supports GitHub and GitHub Enterprise Server.
#[derive(Debug, Parser)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "CLI flag structs naturally accumulate boolean flags; grouping them \
              into a bitflag or sub-struct would not aid clarity here."
)]
#[command(
    name    = "gitssh",
    version,
    about   = "Purpose-built SSH transport client for Git operations against GitHub.",
    long_about = None,
    // Allow unknown arguments beginning with `-o` for OpenSSH compatibility.
    // Any unrecognised args are collected into `extra_opts` below.
    allow_hyphen_values = true,
)]
pub struct Cli {
    /// SSH host to connect to.
    ///
    /// Defaults to `github.com`.  Pass a GHE hostname to target an enterprise
    /// server (requires a matching entry in `~/.config/gitssh/known_hosts`).
    #[arg(index = 1, required_unless_present_any = ["test", "install"])]
    pub host: Option<String>,

    /// Remote command to execute (e.g. `git-upload-pack 'org/repo.git'`).
    ///
    /// All tokens after `<host>` are joined with spaces and passed to the
    /// remote shell verbatim, matching the calling convention Git uses.
    #[arg(index = 2, num_args = 1.., trailing_var_arg = true)]
    pub command: Vec<String>,

    // ── Identity options ──────────────────────────────────────────────────────

    /// Path to the SSH private key to use for authentication.
    ///
    /// If omitted, Gitssh searches `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`,
    /// and `~/.ssh/id_rsa` in that order, then falls back to the SSH agent.
    #[arg(short = 'i', long = "identity", value_name = "FILE")]
    pub identity: Option<PathBuf>,

    /// Path to an OpenSSH certificate to present alongside the key (FR-12).
    #[arg(long = "cert", value_name = "FILE")]
    pub cert: Option<PathBuf>,

    // ── Connection options ─────────────────────────────────────────────────────

    /// SSH port (default: 22; fallback: ssh.github.com:443).
    #[arg(short = 'p', long = "port", value_name = "PORT", default_value_t = 22)]
    pub port: u16,

    // ── Security ──────────────────────────────────────────────────────────────

    /// Skip host-key verification.
    ///
    /// **DANGER:** This disables the MITM protection provided by pinned
    /// fingerprints.  Use only as a last resort (FR-8).
    #[arg(long = "insecure-skip-host-check", action = ArgAction::SetTrue)]
    pub insecure_skip_host_check: bool,

    // ── Diagnostic ────────────────────────────────────────────────────────────

    /// Enable verbose debug logging to stderr.
    #[arg(short = 'v', long = "verbose", action = ArgAction::SetTrue)]
    pub verbose: bool,

    // ── Special modes ─────────────────────────────────────────────────────────

    /// Verify connectivity to github.com and display the server banner (FR-21).
    ///
    /// Connects, authenticates, and prints the GitHub welcome message.
    /// Does not execute any Git command.
    #[arg(long = "test", action = ArgAction::SetTrue, conflicts_with = "install")]
    pub test: bool,

    /// Register Gitssh as the global `core.sshCommand` in Git config (FR-22).
    ///
    /// Runs: `git config --global core.sshCommand 'gitssh'`
    #[arg(long = "install", action = ArgAction::SetTrue, conflicts_with = "test")]
    pub install: bool,

    /// OpenSSH-compatibility options (silently ignored, FR-20).
    ///
    /// Git passes `-o StrictHostKeyChecking=yes` and similar flags; accepting
    /// them here prevents parse errors without honouring their semantics.
    #[arg(short = 'o', value_name = "KEY=VALUE", action = ArgAction::Append, hide = true)]
    pub compat_opts: Vec<String>,
}
