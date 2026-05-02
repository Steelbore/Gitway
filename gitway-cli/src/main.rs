// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
// S3: enforce zero unsafe in all project-owned code at compile time.
#![forbid(unsafe_code)]
//! Gitway CLI entry point.
//!
//! Parses arguments, resolves the identity key (prompting for passphrases if
//! needed), connects to the target host, and either runs `--test` / `--install`
//! or relays the Git command to the remote.

use mimalloc::MiMalloc;

/// Use mimalloc for improved allocation performance on hot paths (M-MIMALLOC-APPS).
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod agent;
mod cli;
mod keygen;
mod sign;

use std::process;

use clap::Parser as _;
use zeroize::{Zeroize as _, Zeroizing};

#[cfg(unix)]
use gitway_lib::auth::connect_agent;
use gitway_lib::auth::{find_identity, IdentityResolution};
use gitway_lib::{GitwayConfig, GitwayError, GitwaySession};

use cli::{Cli, GitwaySubcommand, OutputFormat};

// ── Output mode ───────────────────────────────────────────────────────────────

/// Whether to emit human-readable or machine-readable (JSON) output.
///
/// Applies to `--test`, `--install`, `schema`, `describe`, and the new
/// `keygen` / `sign` subcommands. The exec (git relay) path is always
/// passthrough regardless of mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputMode {
    Human,
    Json,
}

/// Detects the output mode for diagnostic commands.
///
/// Precedence (SFRS Section 4.1):
/// 1. Explicit `--json` or `--format json` flag.
/// 2. `AI_AGENT=1`, `AGENT=1`, or `CI=true` environment variable.
/// 3. stdout is not a terminal (piped) — only checked when `check_tty` is true.
/// 4. Fallback: human.
///
/// `check_tty` is `true` for `--test`, `--install`, `schema`, and `describe`,
/// and `false` for the exec path (where stdout carries binary git-pack data).
fn detect_output_mode(cli: &Cli, check_tty: bool) -> OutputMode {
    use std::io::IsTerminal as _;

    // 1. Explicit flag always wins.
    if cli.json || cli.format == Some(OutputFormat::Json) {
        return OutputMode::Json;
    }

    // 2. Agent / CI environment variable detection (SFRS Section 9).
    if is_agent_or_ci_env() {
        return OutputMode::Json;
    }

    // 3. Piped stdout (only relevant for diagnostic commands, not exec).
    if check_tty && !std::io::stdout().is_terminal() {
        return OutputMode::Json;
    }

    OutputMode::Human
}

/// Returns `true` when a known agent or CI environment variable is set.
fn is_agent_or_ci_env() -> bool {
    std::env::var_os("AI_AGENT").is_some_and(|v| v == "1")
        || std::env::var_os("AGENT").is_some_and(|v| v == "1")
        || std::env::var("CI").is_ok_and(|v| v.eq_ignore_ascii_case("true"))
}

// ── ISO 8601 timestamp (thin wrapper over gitway_lib::time) ──────────────────

/// Returns the current UTC time as an ISO 8601 string.
///
/// Re-exported here as `pub(crate)` so the existing intra-crate callers
/// (`keygen.rs`, `sign.rs`, `agent.rs`) keep compiling unchanged.  The
/// implementation lives in [`gitway_lib::time`] so shim binaries can
/// share it without pulling in the CLI crate.
pub(crate) fn now_iso8601() -> String {
    gitway_lib::time::now_iso8601()
}

// ── JSON emission helpers ─────────────────────────────────────────────────────

/// Emits a structured JSON value to stdout as a single line + newline.
///
/// All Gitway commands that produce JSON output go through this function so
/// a future formatting change (e.g. pretty-printing) applies uniformly.
pub(crate) fn emit_json(value: &serde_json::Value) {
    println!("{value}");
}

/// Emits a single human-readable line to stdout (unlike `eprintln!`, which
/// writes to stderr). Used by commands where the result itself is the
/// payload the user asked for (e.g. `keygen fingerprint`, `keygen verify`).
pub(crate) fn emit_json_line(line: &str) {
    println!("{line}");
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let log_level = if cli.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Warn
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        // Suppress noisy crate logs unless verbose.
        .filter_module(
            "russh",
            if cli.verbose {
                log::LevelFilter::Debug
            } else {
                log::LevelFilter::Off
            },
        )
        .init();

    // Error output mode: use explicit flags or agent env vars, but NOT TTY
    // detection — the exec path has a piped stdout that carries binary data.
    let error_mode = detect_output_mode(&cli, false);
    let invocation = std::env::args().collect::<Vec<_>>().join(" ");

    let exit_code = match run(cli).await {
        Ok(code) => code,
        Err(ref e) => {
            match error_mode {
                OutputMode::Json => {
                    let json = serde_json::json!({
                        "error": {
                            "code": e.error_code(),
                            "exit_code": e.exit_code(),
                            "message": e.to_string(),
                            "hint": e.hint(),
                            "timestamp": now_iso8601(),
                            "command": invocation,
                        }
                    });
                    eprintln!("{json}");
                }
                OutputMode::Human => {
                    // Write all errors to stderr so stdout stays clean (NFR-11).
                    eprintln!("gitway: error: {e}");
                    // Actionable "what to do next" line below the error —
                    // every `GitwayError` kind provides a prescriptive
                    // hint (either call-site-specific via `with_hint` or
                    // the plain-English default from `hint()`).  Keeps
                    // the terminal UX readable without needing to re-read
                    // the technical error message.
                    eprintln!("gitway: what to do: {}", e.hint());
                    // Single-line diagnostic — turns silent exit-128 failures
                    // that git reports when `core.sshCommand` fails into one
                    // grep-able record with PID + argv + exit code + reason.
                    // JSON mode already carries timestamp + command in the
                    // structured blob above, so this is human-mode-only.
                    gitway_lib::diagnostic::emit_for(e);
                }
            }
            e.exit_code()
        }
    };

    // Exit codes from remote processes are 0-255; signal-death codes are
    // 128 + signal (max 128 + 31 = 159 on Linux).  The cast never wraps in
    // practice, but clippy flags it because u32 → i32 is technically lossy.
    #[expect(
        clippy::cast_possible_wrap,
        reason = "exit codes are bounded to 0-255 by POSIX; the cast is safe"
    )]
    process::exit(exit_code as i32);
}

// ── Top-level dispatch ────────────────────────────────────────────────────────

async fn run(cli: Cli) -> Result<u32, GitwayError> {
    // Handle subcommands first — none of them open an SSH connection.
    let mode = detect_output_mode(&cli, true);
    if let Some(subcommand) = cli.subcommand {
        return match subcommand {
            GitwaySubcommand::Schema => Ok(run_schema()),
            GitwaySubcommand::Describe => Ok(run_describe()),
            GitwaySubcommand::Keygen(args) => keygen::run(args.command, mode),
            GitwaySubcommand::Sign(args) => sign::run(&args, mode),
            GitwaySubcommand::Agent(args) => agent::run(args.command, mode).await,
        };
    }

    if cli.install {
        let mode = detect_output_mode(&cli, true);
        return run_install(mode);
    }

    let raw_host = cli
        .host
        .clone()
        .unwrap_or_else(|| gitway_lib::hostkey::DEFAULT_GITHUB_HOST.to_owned());

    // Split off the username if the host arg uses the `user@host` form.
    // Git invokes SSH as: ssh <user>@<host> git-upload-pack ...; for GitHub
    // and other "git" providers <user> is `git`, but AUR uses `aur`,
    // sourcehut uses each user's login, etc.
    let (parsed_user, host) = parse_user_host(&raw_host);

    let mut config_builder = GitwayConfig::builder(&host)
        .port(cli.port)
        .verbose(cli.verbose)
        .skip_host_check(cli.insecure_skip_host_check);

    // Username precedence (matches OpenSSH `ssh -l`):
    //   1. Explicit `-l/--user` on the command line.
    //   2. The `user@` prefix on the host arg.
    //   3. The `GitwayConfig` builder default (`git`).
    if let Some(ref user) = cli.user {
        config_builder = config_builder.username(user.clone());
    } else if let Some(user) = parsed_user {
        config_builder = config_builder.username(user);
    }

    if let Some(ref identity) = cli.identity {
        config_builder = config_builder.identity_file(identity.clone());
    }

    if let Some(ref cert) = cli.cert {
        config_builder = config_builder.cert_file(cert.clone());
    }

    let config = config_builder.build();

    if cli.test {
        let mode = detect_output_mode(&cli, true);
        return run_test(&config, mode).await;
    }

    if cli.command.is_empty() {
        return Err(GitwayError::invalid_config(
            "no remote command specified; pass a git-upload-pack / git-receive-pack command",
        ));
    }

    run_exec(&config, &cli.command).await
}

// ── --test ────────────────────────────────────────────────────────────────────

/// Verifies connectivity and displays the server banner (FR-21).
///
/// In JSON mode emits a structured object to stdout; in human mode prints
/// status lines to stderr (NFR-11).
async fn run_test(config: &GitwayConfig, mode: OutputMode) -> Result<u32, GitwayError> {
    // Collect the passphrase before connecting so the session inactivity
    // timeout does not fire while the user is typing (see `maybe_collect_passphrase`).
    let pre_passphrase = maybe_collect_passphrase(config).await?;

    if mode == OutputMode::Human {
        eprintln!("gitway: connecting to {}:{}…", config.host, config.port);
    }

    let mut session = GitwaySession::connect(config).await?;
    let fingerprint = session.verified_fingerprint();

    if mode == OutputMode::Human {
        eprintln!("gitway: host-key verified ✓");
    }

    let auth_result = if let Some((passphrase, path)) = pre_passphrase {
        session
            .authenticate_with_passphrase(config, &path, &passphrase)
            .await
    } else {
        authenticate_with_prompt(&mut session, config).await
    };

    let authenticated = auth_result.is_ok();
    let no_key = auth_result
        .as_ref()
        .is_err_and(GitwayError::is_no_key_found);

    if mode == OutputMode::Human {
        match &auth_result {
            Ok(()) => {
                eprintln!("gitway: authentication successful ✓");
                if let Some(banner) = session.auth_banner() {
                    eprintln!("{banner}");
                }
            }
            Err(e) if e.is_no_key_found() => {
                eprintln!(
                    "gitway: no identity key found — \
                     use --identity to specify one, or ensure a key exists in ~/.ssh/"
                );
            }
            Err(e) => {
                let _ = session.close().await;
                return Err(GitwayError::invalid_config(e.to_string()));
            }
        }
    }

    let banner = session.auth_banner();
    session.close().await?;

    if mode == OutputMode::Json {
        let json = serde_json::json!({
            "metadata": {
                "tool": "gitway",
                "version": env!("CARGO_PKG_VERSION"),
                "command": format!("gitway --test --host {}", config.host),
                "timestamp": now_iso8601(),
            },
            "data": {
                "host": config.host,
                "port": config.port,
                "host_key_verified": fingerprint.is_some(),
                "fingerprint": fingerprint,
                "authenticated": authenticated,
                "username": config.username,
                "banner": banner,
            }
        });
        println!("{json}");

        // Surface auth errors as a non-zero exit after printing the JSON.
        if let Err(e) = auth_result {
            if !no_key {
                return Err(e);
            }
        }
    }

    Ok(0)
}

// ── Normal exec ───────────────────────────────────────────────────────────────

/// Connects, authenticates, and relays a Git command over the SSH channel.
async fn run_exec(config: &GitwayConfig, command_parts: &[String]) -> Result<u32, GitwayError> {
    // Join all tokens the same way Git does: space-separated.
    let command = command_parts.join(" ");

    // Collect the passphrase before connecting so the session inactivity
    // timeout does not fire while the user is typing (see `maybe_collect_passphrase`).
    let pre_passphrase = maybe_collect_passphrase(config).await?;

    let mut session = GitwaySession::connect(config).await?;

    if let Some((passphrase, path)) = pre_passphrase {
        session
            .authenticate_with_passphrase(config, &path, &passphrase)
            .await?;
    } else {
        authenticate_with_prompt(&mut session, config).await?;
    }

    let exit_code = session.exec(&command).await?;
    session.close().await?;
    Ok(exit_code)
}

// ── --install ─────────────────────────────────────────────────────────────────

/// Writes `core.sshCommand = gitway` to the global Git config (FR-22).
fn run_install(mode: OutputMode) -> Result<u32, GitwayError> {
    let status = std::process::Command::new("git")
        .args(["config", "--global", "core.sshCommand", "gitway"])
        .status()
        .map_err(GitwayError::from)?;

    if status.success() {
        match mode {
            OutputMode::Json => {
                let json = serde_json::json!({
                    "metadata": {
                        "tool": "gitway",
                        "version": env!("CARGO_PKG_VERSION"),
                        "command": "gitway --install",
                        "timestamp": now_iso8601(),
                    },
                    "data": {
                        "configured": true,
                        "config_key": "core.sshCommand",
                        "config_value": "gitway",
                        "scope": "global",
                    }
                });
                println!("{json}");
            }
            OutputMode::Human => {
                eprintln!("gitway: set core.sshCommand = gitway in global Git config ✓");
            }
        }
        Ok(0)
    } else {
        Err(GitwayError::invalid_config(
            "git config --global core.sshCommand failed",
        ))
    }
}

// ── schema subcommand ─────────────────────────────────────────────────────────

/// Emits a JSON Schema (Draft 2020-12) describing all Gitway commands (SFRS Rule 4).
#[expect(
    clippy::too_many_lines,
    reason = "the schema is one large literal — splitting it across helper \
              functions would hurt readability without any structural benefit."
)]
fn run_schema() -> u32 {
    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/steelbore/gitway/schema/v1",
        "title": "gitway",
        "description": "Purpose-built SSH transport client for Git hosting services",
        "version": env!("CARGO_PKG_VERSION"),
        "commands": [
            {
                "name": "gitway <host> <command...>",
                "description": "Relay a Git command over SSH to a hosting service",
                "supports_json": false,
                "idempotent": true,
                "args": {
                    "host": {
                        "type": "string",
                        "description": "SSH hostname (e.g. github.com, gitlab.com, codeberg.org)",
                    },
                    "command": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Remote command tokens (e.g. git-upload-pack 'user/repo.git')",
                    }
                }
            },
            {
                "name": "gitway --test",
                "description": "Verify SSH connectivity and authentication",
                "supports_json": true,
                "idempotent": true,
            },
            {
                "name": "gitway --install",
                "description": "Register gitway as git core.sshCommand globally",
                "supports_json": true,
                "idempotent": true,
            },
            {
                "name": "gitway schema",
                "description": "Emit full JSON Schema for all commands",
                "supports_json": true,
                "idempotent": true,
            },
            {
                "name": "gitway describe",
                "description": "Emit capability manifest for agent/CI discovery",
                "supports_json": true,
                "idempotent": true,
            },
            {
                "name": "gitway keygen <sub>",
                "description": "Generate, inspect, and sign with SSH keys (ssh-keygen subset)",
                "supports_json": true,
                "idempotent": false,
                "subcommands": [
                    "generate", "fingerprint", "extract-public",
                    "change-passphrase", "sign", "verify"
                ]
            },
            {
                "name": "gitway sign",
                "description": "Produce an SSHSIG (OpenSSH file signature) on stdout",
                "supports_json": true,
                "idempotent": true,
            },
            {
                "name": "gitway agent <sub>",
                "description": "Client operations against any SSH agent on $SSH_AUTH_SOCK (Unix-only)",
                "supports_json": true,
                "idempotent": false,
                "subcommands": ["add", "list", "remove", "lock", "unlock"]
            }
        ],
        "binaries": [
            {
                "name": "gitway-keygen",
                "description": "Drop-in shim for `ssh-keygen -Y sign / verify` (byte-compatible stdout)",
                "supports_json": false,
                "use_with": "git -c gpg.format=ssh -c gpg.ssh.program=gitway-keygen"
            },
            {
                "name": "gitway-add",
                "description": "Drop-in shim for `ssh-add` (Unix-only)",
                "supports_json": false,
                "use_with": "tools that invoke `ssh-add` by name (IDEs, credential managers)"
            }
        ],
        "global_flags": {
            "--json": { "type": "boolean", "description": "Emit structured JSON output" },
            "--format": { "type": "string", "enum": ["json"], "description": "Output format" },
            "--no-color": { "type": "boolean", "description": "Disable colored output" },
            "--verbose": { "type": "boolean", "description": "Enable debug logging to stderr" },
            "--identity": { "type": "string", "description": "Path to SSH private key" },
            "--cert": { "type": "string", "description": "Path to OpenSSH certificate" },
            "--user": { "type": "string", "default": "git", "description": "Remote SSH username (e.g. `aur` for AUR; default `git`)" },
            "--port": { "type": "integer", "minimum": 1, "maximum": 65535, "default": 22 },
            "--insecure-skip-host-check": { "type": "boolean", "description": "Skip host-key verification (danger)" },
        },
        "exit_codes": {
            "0": "Success",
            "1": "General / unexpected error",
            "2": "Usage error (bad arguments or configuration)",
            "3": "Not found (no identity key, unknown host)",
            "4": "Permission denied (authentication failure, host key mismatch)",
        }
    });
    println!("{schema}");
    0
}

// ── describe subcommand ───────────────────────────────────────────────────────

/// Emits the capability manifest for agent/CI tool discovery (SFRS Rule 4).
fn run_describe() -> u32 {
    let manifest = serde_json::json!({
        "tool": "gitway",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Purpose-built SSH transport client for Git hosting services (GitHub, GitLab, Codeberg)",
        "commands": [
            {
                "name": "gitway <host> <command...>",
                "description": "Relay a Git command over SSH",
                "supports_json": false,
                "idempotent": true,
            },
            {
                "name": "gitway --test",
                "description": "Verify SSH connectivity and authentication",
                "supports_json": true,
                "idempotent": true,
            },
            {
                "name": "gitway --install",
                "description": "Register gitway as git core.sshCommand globally",
                "supports_json": true,
                "idempotent": true,
            },
            {
                "name": "gitway schema",
                "description": "Emit full JSON Schema for all commands",
                "supports_json": true,
                "idempotent": true,
            },
            {
                "name": "gitway describe",
                "description": "Emit capability manifest for agent/CI discovery",
                "supports_json": true,
                "idempotent": true,
            },
            {
                "name": "gitway keygen",
                "description": "Generate / inspect / sign with SSH keys",
                "supports_json": true,
                "idempotent": false,
            },
            {
                "name": "gitway sign",
                "description": "Produce an SSHSIG file signature",
                "supports_json": true,
                "idempotent": true,
            },
            {
                "name": "gitway agent",
                "description": "Client operations against any SSH agent (Unix-only in v0.5)",
                "supports_json": true,
                "idempotent": false,
            }
        ],
        "companion_binaries": [
            "gitway-keygen",
            "gitway-add"
        ],
        "global_flags": ["--json", "--format", "--verbose", "--no-color",
                         "--insecure-skip-host-check", "--identity", "--cert",
                         "--user", "--port"],
        "output_formats": ["json"],
        "mcp_available": false,
        "providers": ["github.com", "gitlab.com", "codeberg.org"],
    });
    println!("{manifest}");
    0
}

// ── Pre-connection passphrase collection ─────────────────────────────────────

/// Probes the configured identity key and, when a passphrase is required but
/// no SSH agent is available to satisfy authentication, collects the passphrase
/// **before** the SSH connection is opened.
///
/// # Why this matters
///
/// russh enforces a 60-second inactivity timeout (FR-5).  If we prompt for a
/// passphrase *after* connecting, the timer is already running — a user who
/// takes more than a minute to type (or who misses the prompt because it is
/// behind a GUI window) will see a confusing `InactivityTimeout` error.
///
/// By prompting first, the connection is only opened once the passphrase is
/// ready, so the 60-second window is never wasted on user input.
///
/// # Returns
///
/// - `Ok(Some((passphrase, path)))` — passphrase collected; call
///   [`GitwaySession::authenticate_with_passphrase`] directly after connecting.
/// - `Ok(None)` — agent will handle auth, or no file-based key is involved;
///   use the normal [`authenticate_with_prompt`] path.
#[cfg_attr(
    not(unix),
    expect(
        clippy::unused_async,
        reason = "the agent-availability check that requires `.await` is inside \
                  a `#[cfg(unix)]` block; the function stays `async` on every \
                  platform so call sites can `await` it uniformly."
    )
)]
async fn maybe_collect_passphrase(
    config: &GitwayConfig,
) -> Result<Option<(Zeroizing<String>, std::path::PathBuf)>, GitwayError> {
    // Only relevant when an encrypted key file is found.
    let IdentityResolution::Encrypted { path } = find_identity(config)? else {
        return Ok(None);
    };

    // If the SSH agent is reachable and holds at least one identity it can
    // authenticate without a passphrase — let the normal post-connect flow
    // handle it (agent auth completes in < 1 s, well within the timeout).
    #[cfg(unix)]
    if matches!(connect_agent().await, Ok(Some(_))) {
        return Ok(None);
    }

    // No agent (or non-Unix platform) — collect the passphrase now so the
    // SSH session is not sitting idle while the user types.
    log::debug!("auth: collecting passphrase before connecting to avoid inactivity timeout");
    let passphrase = prompt_passphrase(&path)?;
    Ok(Some((passphrase, path)))
}

// ── Shared auth helper ────────────────────────────────────────────────────────

/// Resolves an identity key and authenticates the session.
///
/// If the key is passphrase-protected, the passphrase is collected via
/// [`try_askpass`] (when `SSH_ASKPASS` is set) or [`rpassword`] (terminal).
/// The passphrase string is wrapped in [`Zeroizing`] so its bytes are
/// overwritten before the allocation is released (NFR-3).
async fn authenticate_with_prompt(
    session: &mut GitwaySession,
    config: &GitwayConfig,
) -> Result<(), GitwayError> {
    // Try normal auto-discovery first.
    match session.authenticate_best(config).await {
        Ok(()) => return Ok(()),
        Err(ref e) if e.is_key_encrypted() => {
            // Fall through to passphrase prompt below.
        }
        Err(e) => return Err(e),
    }

    // A key exists but is encrypted — find its path and prompt.
    let IdentityResolution::Encrypted {
        path: encrypted_path,
    } = find_identity(config)?
    else {
        return Err(GitwayError::no_key_found());
    };

    // Zeroizing<String> zeroes the passphrase bytes when the variable is
    // dropped, preventing the secret from lingering in heap memory (NFR-3).
    let passphrase = prompt_passphrase(&encrypted_path)?;
    session
        .authenticate_with_passphrase(config, &encrypted_path, &passphrase)
        .await
}

/// Collects a key passphrase, preferring `SSH_ASKPASS` over a terminal prompt (FR-10).
///
/// Resolution order:
/// 1. [`try_askpass`] — used when `SSH_ASKPASS` is set and the conditions
///    described there are met (GUI environment or `SSH_ASKPASS_REQUIRE` set).
/// 2. [`rpassword`] — falls back to a terminal prompt.
///
/// The returned string is wrapped in [`Zeroizing`] so the bytes are overwritten
/// before the allocation is released (NFR-3).
pub(crate) fn prompt_passphrase(path: &std::path::Path) -> Result<Zeroizing<String>, GitwayError> {
    let prompt = format!("Enter passphrase for {}: ", path.display());

    if let Some(passphrase) = try_askpass(&prompt)? {
        return Ok(passphrase);
    }

    rpassword::prompt_password(&prompt)
        .map(Zeroizing::new)
        .map_err(|e| {
            // ENXIO (os error 6) means no terminal is available — typical when
            // spawned by a GUI app.  Give a helpful hint instead of the raw
            // OS error string.
            if e.raw_os_error() == Some(6) || e.kind() == std::io::ErrorKind::Other {
                GitwayError::invalid_config(
                    "no terminal available for passphrase prompt — \
                     run `ssh-add` to load the key into the SSH agent, \
                     or set SSH_ASKPASS to a GUI passphrase helper \
                     (e.g. ksshaskpass, ssh-askpass-gnome)",
                )
            } else {
                GitwayError::from(e)
            }
        })
}

/// Attempts to collect a passphrase via the `SSH_ASKPASS` program,
/// following OpenSSH conventions (FR-10).
///
/// Returns `Ok(None)` when the askpass path should not be taken.
/// Returns `Ok(Some(_))` with the passphrase when the program succeeded.
/// Returns `Err` when the program was found but could not be launched or
/// exited with a non-zero status.
///
/// # When askpass is used
///
/// Mirrors OpenSSH behavior:
/// - `SSH_ASKPASS_REQUIRE=force` — always use the askpass program.
/// - `SSH_ASKPASS_REQUIRE=prefer` — use it regardless of TTY state.
/// - Otherwise — use it when a display server (`DISPLAY` or
///   `WAYLAND_DISPLAY`) is present **and** stderr is not a terminal
///   (i.e., gitway was spawned by a GUI app without a console).
fn try_askpass(prompt: &str) -> Result<Option<Zeroizing<String>>, GitwayError> {
    use std::io::IsTerminal as _;

    let Some(askpass) = std::env::var_os("SSH_ASKPASS") else {
        return Ok(None);
    };

    // Security: require an absolute path so that a relative value injected
    // into the environment (e.g. by a malicious Git hook or CI pipeline)
    // cannot resolve to an unintended binary via PATH lookup.
    // This is a cheap check (no I/O) so it runs unconditionally before
    // we decide whether askpass is needed at all.
    if !std::path::Path::new(&askpass).is_absolute() {
        return Err(GitwayError::invalid_config(format!(
            "SSH_ASKPASS {askpass:?} must be an absolute path"
        )));
    }

    let require = std::env::var("SSH_ASKPASS_REQUIRE")
        .unwrap_or_default()
        .to_ascii_lowercase();

    let use_askpass = match require.as_str() {
        "force" | "prefer" => true,
        // Default OpenSSH behavior: use askpass when a display server exists
        // but no terminal is attached (spawned by a GUI application).
        _ => {
            let has_display = std::env::var_os("DISPLAY").is_some()
                || std::env::var_os("WAYLAND_DISPLAY").is_some();
            let no_tty = !std::io::stderr().is_terminal();
            has_display && no_tty
        }
    };

    if !use_askpass {
        return Ok(None);
    }

    // On Unix, reject world-writable executables immediately before
    // spawning: any local user could overwrite a world-writable file to
    // intercept passphrases.  The stat is placed here, as close as
    // possible to Command::new, to minimize the TOCTOU window between
    // the permission check and the actual execve(2) call.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(meta) = std::fs::metadata(std::path::Path::new(&askpass)) {
            // 0o002 = write bit for "other"
            if meta.permissions().mode() & 0o002 != 0 {
                return Err(GitwayError::invalid_config(format!(
                    "SSH_ASKPASS {askpass:?} is world-writable and \
                     cannot be trusted"
                )));
            }
        }
    }

    log::debug!("auth: using SSH_ASKPASS program {askpass:?}");

    let output = std::process::Command::new(&askpass)
        .arg(prompt)
        .output()
        .map_err(|e| {
            GitwayError::invalid_config(format!(
                "SSH_ASKPASS program {askpass:?} could not be launched: {e}"
            ))
        })?;

    let status = output.status;
    // Destructure immediately so we hold a mutable Vec<u8> that we can
    // explicitly zeroize before it is dropped — preventing the raw
    // passphrase bytes from lingering on the heap.
    let mut stdout = output.stdout;

    if !status.success() {
        stdout.zeroize();
        return Err(GitwayError::invalid_config(format!(
            "SSH_ASKPASS program {askpass:?} exited with status {status}"
        )));
    }

    // Reject non-UTF-8 output outright: a valid passphrase must be UTF-8,
    // and using from_utf8_lossy would produce an unzeroized Cow<str>
    // intermediate on the heap for invalid input.
    let passphrase = if let Ok(raw) = std::str::from_utf8(&stdout) {
        raw.trim_end_matches('\n').to_owned()
    } else {
        stdout.zeroize();
        return Err(GitwayError::invalid_config(
            "SSH_ASKPASS program returned non-UTF-8 output",
        ));
    };

    // Zero the raw buffer now that the passphrase has been copied out.
    stdout.zeroize();

    // An empty passphrase means the user cancelled the dialog (or the askpass
    // program — e.g. VS Code's ssh-askpass.sh — does not handle SSH key
    // passphrases and returned nothing).  Propagating an empty string would
    // cause an opaque "SshKey: cryptographic error" from the key-decryption
    // layer; return a clear, actionable message instead.
    if passphrase.is_empty() {
        return Err(GitwayError::invalid_config(
            "SSH_ASKPASS program returned an empty passphrase — \
             the dialog was cancelled or the program does not support \
             SSH key passphrase prompts; \
             run `ssh-add ~/.ssh/id_ed25519` to load the key into the \
             SSH agent, or set SSH_ASKPASS to a dedicated passphrase \
             helper (e.g. ksshaskpass, ssh-askpass-gnome)",
        ));
    }

    Ok(Some(Zeroizing::new(passphrase)))
}

// ── Host argument parsing ─────────────────────────────────────────────────────

/// Splits a `[user@]host` argument into its parts.
///
/// Git invokes SSH with the full connection string (`git@github.com`,
/// `aur@aur.archlinux.org`, etc.).  Returns the username portion when
/// present so the caller can pass it to `GitwayConfig::username` instead
/// of falling through to the `git` default.  An empty username (`@host`)
/// is treated as no username — matches OpenSSH's `parse_uri` behaviour.
///
/// # Examples
///
/// ```
/// # use gitway::parse_user_host;
/// assert_eq!(parse_user_host("git@github.com"),
///            (Some("git".to_owned()), "github.com".to_owned()));
/// assert_eq!(parse_user_host("aur@aur.archlinux.org"),
///            (Some("aur".to_owned()), "aur.archlinux.org".to_owned()));
/// assert_eq!(parse_user_host("github.com"),
///            (None, "github.com".to_owned()));
/// assert_eq!(parse_user_host("@github.com"),
///            (None, "github.com".to_owned()));
/// ```
fn parse_user_host(raw: &str) -> (Option<String>, String) {
    match raw.split_once('@') {
        Some((user, host)) if !user.is_empty() => (Some(user.to_owned()), host.to_owned()),
        Some((_empty, host)) => (None, host.to_owned()),
        None => (None, raw.to_owned()),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_host_extracts_git_default() {
        assert_eq!(
            parse_user_host("git@github.com"),
            (Some("git".to_owned()), "github.com".to_owned())
        );
    }

    #[test]
    fn parse_user_host_extracts_non_git_username() {
        // The whole point of the flag: AUR uses `aur`, sourcehut uses the
        // user's login, etc.  The CLI must surface the parsed user so
        // `GitwayConfig::username` is set instead of falling back to `git`.
        assert_eq!(
            parse_user_host("aur@aur.archlinux.org"),
            (Some("aur".to_owned()), "aur.archlinux.org".to_owned())
        );
        assert_eq!(
            parse_user_host("alice@git.sr.ht"),
            (Some("alice".to_owned()), "git.sr.ht".to_owned())
        );
    }

    #[test]
    fn parse_user_host_handles_bare_hostname() {
        assert_eq!(
            parse_user_host("github.com"),
            (None, "github.com".to_owned())
        );
        assert_eq!(
            parse_user_host("ghe.example.com"),
            (None, "ghe.example.com".to_owned())
        );
    }

    #[test]
    fn parse_user_host_treats_empty_user_as_none() {
        // `@host` (no user before the @) should not yield Some("").
        // Matches OpenSSH's parse_uri behaviour.
        assert_eq!(
            parse_user_host("@github.com"),
            (None, "github.com".to_owned())
        );
    }
}
