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

/// Format for verbose / debug records emitted to stderr (PRD §5.8.4
/// FR-68).  Distinct from [`OutputFormat`] — that flag controls
/// command result on stdout (`--test --json`, `--install --json`),
/// while this flag controls the verbose/debug stream on stderr.
/// The two are independent: `gitway --test --json --debug-format=json`
/// emits JSON on stdout for the result envelope AND JSONL on stderr
/// for the verbose/debug events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum DebugFormat {
    /// Readable indented format suitable for an interactive terminal.
    #[default]
    Human,
    /// Newline-delimited JSON, one record per line, for
    /// log-aggregation pipelines.
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
    /// Load, list, remove, or lock keys in a running SSH agent.
    ///
    /// `gitway agent` is the Gitway-native equivalent of `ssh-add`; it
    /// talks to any agent listening on `$SSH_AUTH_SOCK` — Gitway's own
    /// daemon or OpenSSH's. On Windows the socket value is a named
    /// pipe path such as `\\.\pipe\openssh-ssh-agent`.
    Agent(AgentArgs),
    /// Inspect resolved `ssh_config(5)` — the Gitway equivalent of
    /// `ssh -G <host>`.
    ///
    /// `gitway config show <host>` reads `~/.ssh/config` (and
    /// `/etc/ssh/ssh_config` on Unix), expands `Include` directives,
    /// matches the host pattern, and prints the resolved key/value
    /// pairs.  Honours the `--no-config` global flag — useful for
    /// confirming that `ssh_config` is being applied as expected.
    Config(ConfigArgs),
    /// Manage `~/.config/gitway/known_hosts` — add, revoke, list
    /// (M19, PRD §5.8.8 FR-84..FR-87).
    ///
    /// `gitway hosts add <host>` connects to `<host>`, captures the
    /// presented SHA-256 fingerprint without authentication, prompts
    /// for confirmation, and appends a new pin (hashed if the
    /// existing file is hashed; plaintext otherwise).
    /// `gitway hosts revoke <host|fingerprint>` prepends a
    /// `@revoked` line.  `gitway hosts list` prints the resolved
    /// trust set (built-in + user file + CA + revoked) in human or
    /// JSON form.
    Hosts(HostsArgs),
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

// ── Agent arguments (Phase 2) ─────────────────────────────────────────────────

/// Top-level flags + nested subcommand for `gitway agent`.
#[derive(Debug, Args)]
pub struct AgentArgs {
    #[command(subcommand)]
    pub command: AgentSubcommand,
}

/// Subcommands under `gitway agent`.
#[derive(Debug, Subcommand)]
pub enum AgentSubcommand {
    /// Load one or more private keys into the agent (ssh-add equivalent).
    Add(AgentAddArgs),
    /// List identities currently loaded into the agent.
    List(AgentListArgs),
    /// Remove a single identity, or all with `--all`.
    Remove(AgentRemoveArgs),
    /// Lock the agent — it refuses signing until unlocked with the same passphrase.
    Lock(AgentLockArgs),
    /// Unlock a previously-locked agent.
    Unlock(AgentLockArgs),
    /// Start a long-lived Gitway-native SSH agent (Phase 3).
    Start(AgentStartArgs),
    /// Stop the running Gitway agent located via `$SSH_AGENT_PID` or a pid file.
    Stop(AgentStopArgs),
}

/// Arguments for `gitway agent add`.
#[derive(Debug, Args)]
pub struct AgentAddArgs {
    /// Paths to private keys to load. Defaults to `~/.ssh/id_ed25519`
    /// (then `~/.ssh/id_ecdsa`, `~/.ssh/id_rsa`) when omitted.
    #[arg(value_name = "FILE")]
    pub files: Vec<PathBuf>,

    /// Evict the loaded key from the agent after this many seconds
    /// (matches `ssh-add -t`).
    #[arg(short = 't', long = "lifetime", value_name = "SECONDS")]
    pub lifetime: Option<u64>,

    /// Ask the agent to confirm each signing request interactively
    /// (matches `ssh-add -c`). Support is agent-dependent.
    #[arg(short = 'c', long = "confirm", action = ArgAction::SetTrue)]
    pub confirm: bool,
}

/// Arguments for `gitway agent list`.
#[derive(Debug, Args)]
pub struct AgentListArgs {
    /// Print full public keys (matches `ssh-add -L`) instead of the
    /// default short fingerprint listing (`ssh-add -l`).
    #[arg(short = 'L', long = "full", action = ArgAction::SetTrue)]
    pub full: bool,

    /// Fingerprint hash to display.
    #[arg(short = 'E', long = "hash", value_enum, default_value_t = HashKind::Sha256)]
    pub hash: HashKind,
}

/// Arguments for `gitway agent remove`.
#[derive(Debug, Args)]
pub struct AgentRemoveArgs {
    /// Path to a public or private key file to remove by fingerprint.
    #[arg(value_name = "FILE")]
    pub file: Option<PathBuf>,

    /// Remove every identity currently loaded (matches `ssh-add -D`).
    #[arg(long = "all", action = ArgAction::SetTrue, conflicts_with = "file")]
    pub all: bool,
}

/// Arguments for `gitway agent lock` / `unlock`.
#[derive(Debug, Args)]
pub struct AgentLockArgs {
    /// Passphrase (prompted interactively if omitted).
    #[arg(short = 'p', long = "passphrase", value_name = "PASSPHRASE")]
    pub passphrase: Option<String>,
}

/// Arguments for `gitway agent start`.
#[derive(Debug, Args)]
pub struct AgentStartArgs {
    /// Override the socket path. Defaults to
    /// `$XDG_RUNTIME_DIR/gitway-agent.$PID.sock` (falling back to
    /// `$TMPDIR/gitway-agent-<user>/agent.$PID`).
    #[arg(short = 'a', long = "sock", value_name = "PATH")]
    pub sock: Option<PathBuf>,

    /// Default per-key lifetime in seconds. Individual
    /// `gitway agent add -t <sec>` requests override this.
    #[arg(short = 't', long = "default-ttl", value_name = "SECONDS")]
    pub default_ttl: Option<u64>,

    /// Optional pid-file location. Defaults to the runtime-dir
    /// `gitway-agent.pid` next to the socket.
    #[arg(long = "pid-file", value_name = "PATH")]
    pub pid_file: Option<PathBuf>,

    /// Do not daemonize — stay in the foreground, keep stdout/stderr
    /// attached. Matches `ssh-agent -D`. Without this flag the daemon
    /// detaches into the background via `setsid(2)` and prints the
    /// `SSH_AUTH_SOCK` / `SSH_AGENT_PID` eval lines for the shell to
    /// source (just like `ssh-agent`).
    #[arg(short = 'D', long = "foreground", action = ArgAction::SetTrue)]
    pub foreground: bool,

    /// Force Bourne-compatible eval output (`SSH_AUTH_SOCK=...; export …`).
    #[arg(short = 's', long = "sh", action = ArgAction::SetTrue, conflicts_with = "csh")]
    pub sh: bool,

    /// Force csh/fish eval output (`setenv SSH_AUTH_SOCK ...`).
    #[arg(short = 'c', long = "csh", action = ArgAction::SetTrue, conflicts_with = "sh")]
    pub csh: bool,
}

/// Arguments for `gitway agent stop`.
#[derive(Debug, Args)]
pub struct AgentStopArgs {
    /// Pid file to read (default: the agent's advertised location).
    #[arg(long = "pid-file", value_name = "PATH")]
    pub pid_file: Option<PathBuf>,
}

// ── Main CLI struct ───────────────────────────────────────────────────────────

// ── Config arguments (Phase: M12.7) ──────────────────────────────────────────

/// Top-level flags + nested subcommand for `gitway config`.
#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigSubcommand,
}

/// Subcommands under `gitway config`.
#[derive(Debug, Subcommand)]
pub enum ConfigSubcommand {
    /// Resolve effective `ssh_config` for `<host>` (Gitway's `ssh -G`).
    Show(ConfigShowArgs),
}

/// Arguments for `gitway config show`.
#[derive(Debug, Args)]
pub struct ConfigShowArgs {
    /// Host alias to resolve.  Matched against `Host` blocks in the
    /// user and (on Unix) system `ssh_config` files; literal hostname
    /// when the user runs `ssh github.com`.
    #[arg(value_name = "HOST")]
    pub host: String,

    /// Override the user-level `ssh_config` path.  Defaults to
    /// `~/.ssh/config` (or `%USERPROFILE%\.ssh\config` on Windows).
    #[arg(long = "user-config", value_name = "FILE")]
    pub user_config: Option<PathBuf>,

    /// Override the system-level `ssh_config` path.  Defaults to
    /// `/etc/ssh/ssh_config` on Unix and `%PROGRAMDATA%\ssh\ssh_config`
    /// on Windows; pass `--system-config=` (empty value) to disable.
    #[arg(long = "system-config", value_name = "FILE")]
    pub system_config: Option<PathBuf>,

    /// Reveal redacted identity-file paths.  Without this flag,
    /// values matching `*id_*` (no `.pub` suffix) under typical key
    /// directories are displayed as `[REDACTED]` (NFR-20).
    #[arg(long = "show-secrets", action = ArgAction::SetTrue)]
    pub show_secrets: bool,
}

// ── Hosts arguments (M19, PRD §5.8.8) ───────────────────────────────────────

/// Top-level flags + nested subcommand for `gitway hosts`.
#[derive(Debug, Args)]
pub struct HostsArgs {
    #[command(subcommand)]
    pub command: HostsSubcommand,
}

/// Subcommands under `gitway hosts`.
#[derive(Debug, Subcommand)]
pub enum HostsSubcommand {
    /// Connect to `<host>`, capture its SHA-256 host-key fingerprint
    /// without authentication, and (after confirmation) append a pin
    /// to `~/.config/gitway/known_hosts` (FR-85).
    Add(HostsAddArgs),
    /// Prepend a `@revoked` line for `<host_or_fingerprint>` to
    /// `~/.config/gitway/known_hosts` (FR-86).
    Revoke(HostsRevokeArgs),
    /// Print the resolved trust set: embedded fingerprints + user
    /// file pins + matching CAs + matching `@revoked` entries
    /// (FR-87).  Supports `--format=json` for agents.
    List(HostsListArgs),
}

/// Arguments for `gitway hosts add`.
#[derive(Debug, Args)]
pub struct HostsAddArgs {
    /// Host to connect to and pin.  Example: `github.com`,
    /// `ghe.corp.example`, `[bastion.example]:2222`.
    #[arg(value_name = "HOST")]
    pub host: String,

    /// Override the `known_hosts` path.  Defaults to
    /// `~/.config/gitway/known_hosts` via `dirs::config_dir()`.
    #[arg(long = "known-hosts", value_name = "FILE")]
    pub known_hosts: Option<PathBuf>,

    /// Force the new entry to be written in the OpenSSH
    /// `HashKnownHosts yes` form (`|1|salt|hash`).  Without this
    /// flag, the format follows the existing file's convention
    /// (hashed if any line is hashed, plaintext otherwise).
    /// Mutually exclusive with `--no-hash`.
    #[arg(long = "hash", action = ArgAction::SetTrue, conflicts_with = "no_hash")]
    pub hash: bool,

    /// Force the new entry to be written in plaintext form,
    /// regardless of the existing file's convention.  Mutually
    /// exclusive with `--hash`.
    #[arg(long = "no-hash", action = ArgAction::SetTrue, conflicts_with = "hash")]
    pub no_hash: bool,

    /// Append the entry without prompting for confirmation.
    /// Required when stdin is not a terminal or when running with
    /// `--json` / `AI_AGENT=1` / `CI=true`.
    #[arg(short = 'y', long = "yes", action = ArgAction::SetTrue)]
    pub yes: bool,
}

/// Arguments for `gitway hosts revoke`.
#[derive(Debug, Args)]
pub struct HostsRevokeArgs {
    /// Either a host pattern (`github.com`, `*.example.com`) or a
    /// SHA-256 fingerprint (`SHA256:...`).  Host-pattern inputs
    /// produce one `@revoked` line per matching fingerprint
    /// resolved through `host_key_trust`; fingerprint inputs
    /// produce a single `@revoked * <fp>` line.
    #[arg(value_name = "HOST_OR_FINGERPRINT")]
    pub input: String,

    /// Override the `known_hosts` path.  Defaults to
    /// `~/.config/gitway/known_hosts`.
    #[arg(long = "known-hosts", value_name = "FILE")]
    pub known_hosts: Option<PathBuf>,
}

/// Arguments for `gitway hosts list`.
#[derive(Debug, Args)]
pub struct HostsListArgs {
    /// Override the `known_hosts` path.  Defaults to
    /// `~/.config/gitway/known_hosts`.
    #[arg(long = "known-hosts", value_name = "FILE")]
    pub known_hosts: Option<PathBuf>,
}

/// Gitway — pure-Rust SSH toolkit for Git: transport, keys, signing, agent.
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
    about   = "Pure-Rust SSH toolkit for Git: transport, keys, signing, agent.",
    long_about = None,
    after_help = "\
Project page:  https://gitway.steelbore.com/
Maintainer:    Mohamed Hammad <Mohamed.Hammad@Steelbore.com>
Copyright:     (C) 2026 Mohamed Hammad — GPL-3.0-or-later",
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

    /// Remote SSH username.
    ///
    /// Most Git hosts use `git` (GitHub, GitLab, Codeberg, GHE), which is
    /// the default when this flag is omitted.  Some services use a different
    /// account: Arch User Repository uses `aur`, sourcehut uses each user's
    /// own login, etc.  Equivalent to `ssh -l <user>`.
    ///
    /// If both `--user` and the `user@host` form are supplied, `--user`
    /// takes precedence (matches OpenSSH).
    #[arg(short = 'l', long = "user", value_name = "USER")]
    pub user: Option<String>,

    // ── Connection options ────────────────────────────────────────────────────
    /// SSH port.
    ///
    /// Defaults to the `Port` directive from `ssh_config(5)` if set
    /// for the target host, or 22 otherwise.  Explicit `--port` always
    /// wins (matches OpenSSH precedence).
    #[arg(short = 'p', long = "port", value_name = "PORT")]
    pub port: Option<u16>,

    // ── Security ──────────────────────────────────────────────────────────────
    /// Skip host-key verification.
    ///
    /// **DANGER:** This disables the MITM protection provided by pinned
    /// fingerprints.  Use only as a last resort (FR-8).
    #[arg(long = "insecure-skip-host-check", action = ArgAction::SetTrue)]
    pub insecure_skip_host_check: bool,

    /// Do not read any `ssh_config(5)` files.  Equivalent to OpenSSH's
    /// `-F /dev/null` — useful when reproducing connection failures
    /// from an unconfigured environment, or when ssh_config-derived
    /// values are causing trouble.
    #[arg(long = "no-config", action = ArgAction::SetTrue)]
    pub no_config: bool,

    // ── Proxy / jump options (M13) ────────────────────────────────────────────
    /// Connect via this `ProxyCommand` template instead of TCP
    /// (FR-55).  Overrides any `ProxyCommand` from `ssh_config(5)`.
    /// Pass `none` (case-insensitive) to disable a config-supplied
    /// `ProxyCommand` and force a direct connection.
    ///
    /// `%h`, `%p`, `%r`, `%n`, and `%%` are expanded against the
    /// resolved hostname / port / remote-user / original-alias before
    /// the platform shell (`sh -c` / `cmd /C`) runs the command.
    #[arg(long = "proxy-command", value_name = "COMMAND")]
    pub proxy_command: Option<String>,

    /// Connect via one or more `ProxyJump` bastions (FR-56).
    /// Repeatable; matches OpenSSH's `-J` flag in shape.  Each value
    /// follows the `[user@]host[:port]` form; multiple `-J` flags
    /// build a chain of up to 8 hops in order.
    ///
    /// Pass `none` (case-insensitive) as the only value to disable a
    /// config-supplied `ProxyJump`.  Per-hop host-key verification
    /// always runs independently — mismatch at any hop aborts the
    /// entire chain (NFR-17).
    #[arg(short = 'J', long = "jump-host", value_name = "[USER@]HOST[:PORT]", action = ArgAction::Append)]
    pub jump_host: Vec<String>,

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
    /// Enable verbose debug logging to stderr (FR-65).  Repeatable —
    /// `-v` / `-vv` / `-vvv` produce additive depth (FR-66):
    ///
    /// - `-v`   — info-level events from anvil-ssh and gitway.
    /// - `-vv`  — debug-level events including russh handshake details.
    /// - `-vvv` — trace-level events including every applied
    ///   `~/.ssh/config` directive (with file + line), every
    ///   identity tried (path, fingerprint, algorithm, verdict),
    ///   every channel open / close (with channel id), and every
    ///   protocol message type with size.
    ///
    /// Output goes exclusively to stderr (FR-67) so the stdout-clean
    /// invariant for the exec / `--test --json` paths is preserved.
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    pub verbose: u8,

    /// Format for verbose / debug records emitted to stderr (FR-68).
    ///
    /// - `human` (default) — readable indented format suitable for an
    ///   interactive terminal.
    /// - `json` — newline-delimited JSON (one record per line) for
    ///   log-aggregation pipelines.  Each record carries `ts` (RFC
    ///   3339 UTC), `level`, `category` (the tracing target), and
    ///   `message` keys, plus any structured fields the call site
    ///   provided (e.g. `host`, `fp`, `verdict` for host-key events).
    ///
    /// Stdout is unchanged regardless of this flag — it stays clean
    /// for the exec passthrough and `--test --json` envelope.
    #[arg(long = "debug-format", value_enum, default_value_t = DebugFormat::Human)]
    pub debug_format: DebugFormat,

    /// Comma-separated list of tracing categories to enable at the
    /// active verbosity level (FR-69).  Recognized values come from
    /// [`anvil_ssh::log::CATEGORIES`] (`anvil_ssh::kex`,
    /// `anvil_ssh::auth`, `anvil_ssh::channel`, `anvil_ssh::config`)
    /// plus the synthetic `russh` for russh's own debug output.
    ///
    /// When set, only the listed categories produce events at
    /// `trace`/`debug`/`info` levels — everything else is filtered to
    /// `warn`.  This lets `gitway -vvv --debug-categories=kex,auth`
    /// give an operator the full handshake + auth picture without the
    /// `~/.ssh/config` directive firehose.
    ///
    /// Short forms (`kex`, `auth`, `channel`, `config`) are accepted
    /// and expand to the `anvil_ssh::*` long form internally.
    #[arg(
        long = "debug-categories",
        value_delimiter = ',',
        num_args = 1..,
    )]
    pub debug_categories: Vec<String>,

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
