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

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

// ── Output format ─────────────────────────────────────────────────────────────

/// Machine-readable output format (SFRS Rule 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Structured JSON (for agents, CI pipelines, and shell scripting).
    Json,
}

// ── Subcommands ───────────────────────────────────────────────────────────────

/// Optional subcommands for agent/CI discovery and key operations (SFRS Rule 4).
#[derive(Debug, Subcommand)]
pub enum GitwaySubcommand {
    /// Emit the full JSON Schema (Draft 2020-12) for all Gitway commands.
    ///
    /// Output is always JSON regardless of `--format`.
    Schema,
    /// Emit the capability manifest for agent/CI discovery.
    ///
    /// Lists commands, flags, and output format support.
    /// Output is always JSON regardless of `--format`.
    Describe,
    /// Generate, inspect, and sign with SSH keys.
    ///
    /// `gitway keygen` replaces the subset of `ssh-keygen` needed for
    /// day-to-day git workflows: generate keys, print fingerprints, and
    /// produce / verify SSHSIG signatures.
    Keygen(KeygenArgs),
    /// Produce an SSHSIG signature over data read from a file or stdin.
    ///
    /// Ergonomic alias for `gitway keygen sign` with a flat flag layout.
    Sign(SignArgs),
}

// ── Keygen arguments ──────────────────────────────────────────────────────────

/// Top-level flags + nested subcommand for `gitway keygen`.
#[derive(Debug, Args)]
pub struct KeygenArgs {
    #[command(subcommand)]
    pub command: KeygenSubcommand,
}

/// Subcommands under `gitway keygen`.
#[derive(Debug, Subcommand)]
pub enum KeygenSubcommand {
    /// Generate a new keypair.
    Generate(GenerateArgs),
    /// Print the fingerprint of an existing public key.
    Fingerprint(FingerprintArgs),
    /// Write the public key derived from a private key file.
    ExtractPublic(ExtractPublicArgs),
    /// Change (add / remove) the passphrase on an existing private key.
    ChangePassphrase(ChangePassphraseArgs),
    /// Sign data under a namespace, producing an armored SSHSIG on stdout.
    Sign(SignArgs),
    /// Verify an SSHSIG against an allowed-signers file.
    Verify(VerifyArgs),
}

/// The key algorithm selectable on the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KeyAlg {
    /// Ed25519 (recommended; 256-bit).
    Ed25519,
    /// ECDSA. Use `--bits 256 | 384 | 521` to select the curve.
    Ecdsa,
    /// RSA. Use `--bits` to pick the modulus size (default 3072).
    Rsa,
}

/// The hash algorithm for fingerprints and SSHSIG message digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HashKind {
    /// SHA-256 — the OpenSSH default for fingerprints.
    Sha256,
    /// SHA-512 — the default for SSHSIG preambles.
    Sha512,
}

/// Arguments for `gitway keygen generate`.
#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// Key algorithm (ed25519 | ecdsa | rsa).
    #[arg(short = 't', long = "type", value_enum, default_value_t = KeyAlg::Ed25519)]
    pub kind: KeyAlg,

    /// Key size in bits (ECDSA: 256|384|521; RSA: 2048..16384).
    #[arg(short = 'b', long = "bits")]
    pub bits: Option<u32>,

    /// Output path for the private key. `<path>.pub` is written alongside.
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub file: PathBuf,

    /// Passphrase used to encrypt the private key.
    ///
    /// If omitted and `--no-passphrase` is not given, Gitway prompts
    /// interactively via `rpassword` / `SSH_ASKPASS`.
    #[arg(short = 'N', long = "passphrase", value_name = "PASSPHRASE")]
    pub passphrase: Option<String>,

    /// Leave the generated key unencrypted.
    #[arg(long = "no-passphrase", action = ArgAction::SetTrue, conflicts_with = "passphrase")]
    pub no_passphrase: bool,

    /// Comment recorded in the key file (defaults to `user@host`).
    #[arg(short = 'C', long = "comment", value_name = "COMMENT")]
    pub comment: Option<String>,
}

/// Arguments for `gitway keygen fingerprint`.
#[derive(Debug, Args)]
pub struct FingerprintArgs {
    /// Path to a private or public key file.
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub file: PathBuf,

    /// Hash algorithm.
    #[arg(long = "hash", value_enum, default_value_t = HashKind::Sha256)]
    pub hash: HashKind,
}

/// Arguments for `gitway keygen extract-public`.
#[derive(Debug, Args)]
pub struct ExtractPublicArgs {
    /// Path to the private key file.
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub file: PathBuf,

    /// Output path for the public key; defaults to `<FILE>.pub`.
    #[arg(short = 'o', long = "output", value_name = "OUT")]
    pub output: Option<PathBuf>,
}

/// Arguments for `gitway keygen change-passphrase`.
#[derive(Debug, Args)]
pub struct ChangePassphraseArgs {
    /// Path to the existing private key.
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub file: PathBuf,

    /// Existing passphrase (prompted if omitted and needed).
    #[arg(short = 'P', long = "old-passphrase", value_name = "PASSPHRASE")]
    pub old_passphrase: Option<String>,

    /// Target passphrase (prompted if omitted; implies encryption).
    #[arg(short = 'N', long = "new-passphrase", value_name = "PASSPHRASE")]
    pub new_passphrase: Option<String>,

    /// Remove the passphrase entirely (leave the key unencrypted).
    #[arg(long = "no-passphrase", action = ArgAction::SetTrue, conflicts_with = "new_passphrase")]
    pub no_passphrase: bool,
}

/// Arguments for `gitway sign` and `gitway keygen sign`.
#[derive(Debug, Args)]
pub struct SignArgs {
    /// Private key file to sign with. If omitted, the same discovery order
    /// as the transport path is used (`~/.ssh/id_ed25519`, etc.).
    #[arg(short = 'f', long = "key", value_name = "FILE")]
    pub key: Option<PathBuf>,

    /// Namespace for the signature (git uses `git`).
    #[arg(short = 'n', long = "namespace", value_name = "NS")]
    pub namespace: String,

    /// Input file; `-` or omitted reads stdin.
    #[arg(short = 'i', long = "input", value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// Output file; `-` or omitted writes to stdout.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Message hash algorithm embedded in the SSHSIG preamble.
    #[arg(long = "hash", value_enum, default_value_t = HashKind::Sha512)]
    pub hash: HashKind,
}

/// Arguments for `gitway keygen verify`.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Signer identity (e.g. an email address) used to look up authorized
    /// principals in the allowed-signers file.
    #[arg(short = 'I', long = "signer", value_name = "IDENTITY")]
    pub signer: String,

    /// Namespace; must match the namespace embedded in the signature.
    #[arg(short = 'n', long = "namespace", value_name = "NS")]
    pub namespace: String,

    /// Path to an allowed-signers file mapping principals to public keys.
    #[arg(long = "allowed-signers", value_name = "FILE")]
    pub allowed_signers: PathBuf,

    /// Armored SSHSIG signature file produced by `gitway sign`
    /// or `ssh-keygen -Y sign`.
    #[arg(short = 's', long = "signature", value_name = "FILE")]
    pub signature: PathBuf,

    /// Input file; `-` or omitted reads stdin.
    #[arg(short = 'i', long = "input", value_name = "FILE")]
    pub input: Option<PathBuf>,
}

// ── Main CLI struct ───────────────────────────────────────────────────────────

/// Gitway — purpose-built SSH transport client for Git hosting services.
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
    pub subcommand: Option<GitwaySubcommand>,

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
    /// If omitted, Gitway searches `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`,
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

    /// Register Gitway as the global `core.sshCommand` in Git config (FR-22).
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
