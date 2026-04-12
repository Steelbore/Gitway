// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Clap command-line interface definitions (FR-18, FR-19, FR-20, FR-21, FR-22).
//!
//! Invocation:
//! ```text
//! gitway [OPTIONS] <host> <command...>
//! gitway --test [OPTIONS]
//! gitway --install
//! gitway schema
//! gitway describe
//! ```
//!
//! Unknown `-o Key=Value` OpenSSH options are silently ignored for compatibility
//! with `GIT_SSH_COMMAND` / `core.sshCommand` invocations (FR-20).

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};

// ── Output format ─────────────────────────────────────────────────────────────

/// Machine-readable output format (SFRS Rule 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Structured JSON (for agents, CI pipelines, and shell scripting).
    Json,
}

// ── Subcommands ───────────────────────────────────────────────────────────────

/// Optional subcommands for agent/CI discovery (SFRS Rule 4).
#[derive(Debug, Subcommand)]
pub enum GitsshSubcommand {
    /// Emit the full JSON Schema (Draft 2020-12) for all Gitssh commands.
    ///
    /// Output is always JSON regardless of `--format`.
    Schema,
    /// Emit the capability manifest for agent/CI discovery.
    ///
    /// Lists commands, flags, and output format support.
    /// Output is always JSON regardless of `--format`.
    Describe,
}

// ── Main CLI struct ───────────────────────────────────────────────────────────

/// Gitssh — purpose-built SSH transport client for Git hosting services.
///
/// Acts as a drop-in replacement for `ssh` when used with `GIT_SSH_COMMAND`
/// or `core.sshCommand`.  Supports GitHub, GitLab, Codeberg, and any
/// self-hosted Git instance whose fingerprints are in
/// `~/.config/gitway/known_hosts`.
#[derive(Debug, Parser)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "CLI flag structs naturally accumulate boolean flags; grouping them \
              into a bitflag or sub-struct would not aid clarity here."
)]
#[command(
    name    = "gitway",
    version,
    about   = "Purpose-built SSH transport client for Git operations against GitHub, GitLab, and Codeberg.",
    long_about = None,
    // Allow unknown arguments beginning with `-o` for OpenSSH compatibility.
    // Any unrecognised args are collected into `extra_opts` below.
    allow_hyphen_values = true,
    // When a subcommand name is provided (e.g. `gitway schema`), the
    // `host` positional arg requirement is automatically waived.
    subcommand_negates_reqs = true,
    // A word matching a subcommand name (e.g. "schema") is treated as a
    // subcommand even when positional args are also defined.
    subcommand_precedence_over_arg = true,
)]
pub struct Cli {
    // ── Subcommands ───────────────────────────────────────────────────────────

    #[command(subcommand)]
    pub subcommand: Option<GitsshSubcommand>,

    // ── Positional arguments ──────────────────────────────────────────────────

    /// SSH host to connect to.
    ///
    /// Defaults to `github.com`.  Well-known hosts with embedded fingerprints:
    /// `github.com`, `gitlab.com`, `codeberg.org`.  Any other host requires a
    /// matching entry in `~/.config/gitway/known_hosts`.
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

    // ── Connection options ────────────────────────────────────────────────────

    /// SSH port (default: 22).
    #[arg(short = 'p', long = "port", value_name = "PORT", default_value_t = 22)]
    pub port: u16,

    // ── Security ──────────────────────────────────────────────────────────────

    /// Skip host-key verification.
    ///
    /// **DANGER:** This disables the MITM protection provided by pinned
    /// fingerprints.  Use only as a last resort (FR-8).
    #[arg(long = "insecure-skip-host-check", action = ArgAction::SetTrue)]
    pub insecure_skip_host_check: bool,

    // ── Output format (SFRS Rule 1) ───────────────────────────────────────────

    /// Emit structured JSON output (shorthand for `--format json`).
    ///
    /// Applies to `--test` and `--install`.  Errors are also written to
    /// stderr as JSON when this flag is active.
    #[arg(long = "json", action = ArgAction::SetTrue, overrides_with = "format")]
    pub json: bool,

    /// Output format for diagnostic commands (`--test`, `--install`).
    ///
    /// Omit for auto-detection: JSON is selected when `AI_AGENT=1`,
    /// `AGENT=1`, `CI=true`, or stdout is not a terminal.
    #[arg(long = "format", value_enum, value_name = "FORMAT")]
    pub format: Option<OutputFormat>,

    /// Disable colored output (honours the `NO_COLOR` convention).
    #[arg(long = "no-color", action = ArgAction::SetTrue)]
    pub no_color: bool,

    // ── Diagnostic ────────────────────────────────────────────────────────────

    /// Enable verbose debug logging to stderr.
    #[arg(short = 'v', long = "verbose", action = ArgAction::SetTrue)]
    pub verbose: bool,

    // ── Special modes ─────────────────────────────────────────────────────────

    /// Verify connectivity to the target host and display the server banner (FR-21).
    ///
    /// Connects, authenticates, and prints the welcome message.
    /// Supports `--json` / `--format json` for structured output.
    /// Does not execute any Git command.
    #[arg(long = "test", action = ArgAction::SetTrue, conflicts_with = "install")]
    pub test: bool,

    /// Register Gitssh as the global `core.sshCommand` in Git config (FR-22).
    ///
    /// Runs: `git config --global core.sshCommand 'gitway'`
    /// Supports `--json` / `--format json` for structured output.
    #[arg(long = "install", action = ArgAction::SetTrue, conflicts_with = "test")]
    pub install: bool,

    /// OpenSSH-compatibility options (silently ignored, FR-20).
    ///
    /// Git passes `-o StrictHostKeyChecking=yes` and similar flags; accepting
    /// them here prevents parse errors without honouring their semantics.
    #[arg(short = 'o', value_name = "KEY=VALUE", action = ArgAction::Append, hide = true)]
    pub compat_opts: Vec<String>,
}
