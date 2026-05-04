// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Dispatcher for the `gitway hosts` subcommand tree (M19, PRD §5.8.8).
//!
//! Three verbs:
//!
//! - **`add <host>`** — connect, capture fingerprint without
//!   authentication, prompt for confirmation, append a pin
//!   (hashed if file is hashed; plaintext otherwise).
//! - **`revoke <host_or_fingerprint>`** — prepend a `@revoked` line.
//! - **`list`** — print the resolved trust set (embedded + direct
//!   pins + cert authorities + revoked) in human or JSON form.
//!
//! All three verbs honour `--known-hosts` to override the default
//! `~/.config/gitway/known_hosts` location.  All output respects
//! NFR-11: stdout stays clean (only the `--json` envelope on `list`
//! lands on stdout); status, prompts, and tracing go to stderr.

use std::io::IsTerminal as _;
use std::path::PathBuf;

use anvil_ssh::cert_authority::parse_known_hosts;
use anvil_ssh::hostkey::{
    all_embedded, append_known_host, append_known_host_hashed, default_known_hosts_path,
    detect_hash_mode, prepend_revoked, HashMode,
};
use anvil_ssh::ssh_config::StrictHostKeyChecking;
use anvil_ssh::{AnvilConfig, AnvilError, AnvilSession};

use crate::cli::{HostsAddArgs, HostsListArgs, HostsRevokeArgs, HostsSubcommand};
use crate::{emit_json, now_iso8601, OutputMode};

// ── Exit codes (SFRS Rule 2 + M19 plan) ─────────────────────────────────────

/// Exit code 73 — user typed `n` at the FR-85 confirmation prompt.
const EXIT_USER_DECLINED: u32 = 73;
/// Exit code 78 — interactive input is required but unavailable
/// (`--json` / piped stdin / agent env without `--yes`).
const EXIT_NEEDS_YES: u32 = 78;

/// Dispatches one `gitway hosts <sub>` invocation.
///
/// # Errors
///
/// Returns the underlying `AnvilError` from each verb's
/// implementation.
pub fn run(sub: HostsSubcommand, mode: OutputMode) -> Result<u32, AnvilError> {
    // tokio runtime for the FR-85 connect path; `revoke` and `list`
    // are sync but it's cheap to set this up unconditionally.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            AnvilError::invalid_config(format!("could not start tokio runtime for hosts: {e}"))
        })?;
    rt.block_on(async {
        match sub {
            HostsSubcommand::Add(args) => run_add(args, mode).await,
            HostsSubcommand::Revoke(args) => run_revoke(&args, mode),
            HostsSubcommand::List(args) => run_list(&args, mode),
        }
    })
}

/// Resolves the `known_hosts` path the verb should target — `--known-hosts`
/// override if present, else the default `~/.config/gitway/known_hosts`.
fn resolve_path(override_path: Option<PathBuf>) -> Result<PathBuf, AnvilError> {
    if let Some(p) = override_path {
        return Ok(p);
    }
    default_known_hosts_path().ok_or_else(|| {
        AnvilError::invalid_config(
            "could not resolve default known_hosts path; \
             pass --known-hosts to override"
                .to_owned(),
        )
    })
}

// ── add ─────────────────────────────────────────────────────────────────────

#[allow(
    clippy::too_many_lines,
    reason = "Single async dispatcher covering probe + hash-mode detect + interactive prompt + write + dual-mode output. Splitting at any of these would obscure the FR-85 safety property (no auth packets sent, ever) by spreading the AnvilSession lifecycle across multiple fns. ~115 lines of straight-line orchestration."
)]
async fn run_add(args: HostsAddArgs, mode: OutputMode) -> Result<u32, AnvilError> {
    let path = resolve_path(args.known_hosts.clone())?;

    // Probe: connect with StrictHostKeyChecking::No so an unknown
    // host doesn't reject; capture the fingerprint via the existing
    // verified_fingerprint() API; close immediately.  Never call
    // authenticate_* — we are explicitly not sending any
    // credentials.  M19 plan FR-85 safety guarantee.
    let probe_dir = tempfile::tempdir().map_err(|e| {
        AnvilError::invalid_config(format!("could not create temp dir for probe: {e}"))
    })?;
    let probe_known_hosts = probe_dir.path().join("probe_known_hosts");
    let probe_config = AnvilConfig::builder(&args.host)
        .strict_host_key_checking(StrictHostKeyChecking::No)
        .custom_known_hosts(probe_known_hosts)
        .build();

    let session = AnvilSession::connect(&probe_config).await?;
    let fingerprint = session.verified_fingerprint().ok_or_else(|| {
        AnvilError::invalid_config(
            "host-key fingerprint was not captured during probe \
                 (StrictHostKeyChecking::No path should always set it)"
                .to_owned(),
        )
    })?;
    session.close().await?;

    // Decide hash vs plaintext.  --hash and --no-hash override the
    // file-format auto-detect.
    let hashed = if args.hash {
        true
    } else if args.no_hash {
        false
    } else {
        match detect_hash_mode(&path)? {
            HashMode::Hashed => true,
            HashMode::Plaintext | HashMode::Empty => false,
        }
    };

    // Display + confirmation.  Stderr only — stdout is reserved for
    // the JSON envelope when --json is set.
    eprintln!(
        "gitway hosts add: {host} — fingerprint {fp}",
        host = args.host,
        fp = fingerprint,
    );

    let prompt_required = !args.yes;
    if prompt_required {
        let stdin_is_tty = std::io::stdin().is_terminal();
        if mode == OutputMode::Json || !stdin_is_tty {
            // Non-interactive context — refuse rather than guess at
            // intent.  Tip-style hint to stderr; exit 78 ("interactive
            // input required") so a wrapper script can detect this
            // without parsing the message text.
            eprintln!(
                "gitway hosts add: refusing without --yes — interactive \
                 confirmation required when stdin is not a TTY (or under \
                 --json / AI_AGENT=1).\n\
                 \n\
                 Tip: re-run with `--yes` to append unconditionally:\n\
                 \n\
                     gitway hosts add --yes {host}",
                host = args.host,
            );
            return Ok(EXIT_NEEDS_YES);
        }
        eprint!("Append this fingerprint to {}? [y/N] ", path.display());
        let _ = std::io::Write::flush(&mut std::io::stderr());
        let mut response = String::new();
        std::io::stdin()
            .read_line(&mut response)
            .map_err(|e| AnvilError::invalid_config(format!("could not read stdin: {e}")))?;
        let trimmed = response.trim().to_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            eprintln!("gitway hosts add: declined; no changes written.");
            return Ok(EXIT_USER_DECLINED);
        }
    }

    // Write.
    tracing::debug!(
        target: anvil_ssh::log::CAT_CONFIG,
        host = %args.host,
        fp = %fingerprint,
        hash_mode = if hashed { "hashed" } else { "plaintext" },
        "hosts_add appending entry",
    );
    if hashed {
        append_known_host_hashed(&path, &args.host, &fingerprint)?;
    } else {
        append_known_host(&path, &args.host, &fingerprint)?;
    }

    if mode == OutputMode::Json {
        let envelope = serde_json::json!({
            "metadata": {
                "tool": "gitway",
                "version": env!("CARGO_PKG_VERSION"),
                "command": "gitway hosts add",
                "timestamp": now_iso8601(),
            },
            "data": {
                "host": args.host,
                "fingerprint": fingerprint,
                "known_hosts_path": path.display().to_string(),
                "hashed": hashed,
            },
        });
        emit_json(&envelope);
    } else {
        eprintln!(
            "gitway hosts add: appended {host} {fp} to {path} ({mode})",
            host = args.host,
            fp = fingerprint,
            path = path.display(),
            mode = if hashed { "hashed" } else { "plaintext" },
        );
    }

    Ok(0)
}

// ── revoke ──────────────────────────────────────────────────────────────────

fn run_revoke(args: &HostsRevokeArgs, mode: OutputMode) -> Result<u32, AnvilError> {
    let path = resolve_path(args.known_hosts.clone())?;
    let input = args.input.trim();

    // Classify input: SHA256:... = fingerprint; everything else = host.
    let (host_pattern, fingerprint) = if input.starts_with("SHA256:") {
        // Single revoke line, host pattern `*`.
        ("*".to_owned(), input.to_owned())
    } else {
        // Host-pattern input: resolve via host_key_trust, prepend one
        // @revoked line per matching fingerprint.
        let trust = anvil_ssh::hostkey::host_key_trust(input, &Some(path.clone()))?;
        if trust.fingerprints.is_empty() {
            return Err(AnvilError::invalid_config(format!(
                "no fingerprints known for host '{input}'; \
                 nothing to revoke. Pass a SHA256:... fingerprint to \
                 revoke a specific key unconditionally, or run \
                 `gitway hosts add {input}` first."
            )));
        }
        // For now: revoke just the first matched fingerprint.  Multi-fp
        // batch revoke is a v1.1 polish item.
        (input.to_owned(), trust.fingerprints[0].clone())
    };

    tracing::debug!(
        target: anvil_ssh::log::CAT_CONFIG,
        input = %input,
        host_pattern = %host_pattern,
        fp = %fingerprint,
        "hosts_revoke prepending @revoked line",
    );
    prepend_revoked(&path, &host_pattern, &fingerprint)?;

    if mode == OutputMode::Json {
        let envelope = serde_json::json!({
            "metadata": {
                "tool": "gitway",
                "version": env!("CARGO_PKG_VERSION"),
                "command": "gitway hosts revoke",
                "timestamp": now_iso8601(),
            },
            "data": {
                "host_pattern": host_pattern,
                "fingerprint": fingerprint,
                "known_hosts_path": path.display().to_string(),
            },
        });
        emit_json(&envelope);
    } else {
        eprintln!(
            "gitway hosts revoke: prepended @revoked {host_pattern} {fingerprint} to {path}",
            path = path.display(),
        );
    }

    Ok(0)
}

// ── list ────────────────────────────────────────────────────────────────────

#[allow(
    clippy::too_many_lines,
    reason = "Single dispatcher emits two output modes (human + JSON) plus structured tracing — splitting at the human/JSON boundary obscures the read-flow. The function is ~110 lines of straight-line printing/JSON assembly with no branching complexity."
)]
fn run_list(args: &HostsListArgs, mode: OutputMode) -> Result<u32, AnvilError> {
    let path = resolve_path(args.known_hosts.clone())?;
    let parsed = if path.exists() {
        let content = std::fs::read_to_string(&path).map_err(|e| {
            AnvilError::invalid_config(format!(
                "could not read known_hosts {}: {e}",
                path.display(),
            ))
        })?;
        parse_known_hosts(&content)?
    } else {
        anvil_ssh::cert_authority::KnownHostsFile::default()
    };
    let embedded = all_embedded();

    tracing::debug!(
        target: anvil_ssh::log::CAT_CONFIG,
        embedded_count = embedded.len(),
        direct_count = parsed.direct.len(),
        ca_count = parsed.cert_authorities.len(),
        revoked_count = parsed.revoked.len(),
        hashed_count = parsed.hashed.len(),
        "hosts_list aggregated trust set",
    );

    if mode == OutputMode::Json {
        let embedded_json: Vec<serde_json::Value> = embedded
            .iter()
            .map(|(host, fp, alg)| {
                serde_json::json!({
                    "host": host,
                    "fingerprint": fp,
                    "algorithm": alg,
                })
            })
            .collect();
        let direct_json: Vec<serde_json::Value> = parsed
            .direct
            .iter()
            .map(|d| {
                serde_json::json!({
                    "host_pattern": d.host_pattern,
                    "fingerprint": d.fingerprint,
                    "hashed": false,
                })
            })
            .chain(parsed.hashed.iter().map(|entry| {
                serde_json::json!({
                    "host_pattern": "(hashed)",
                    "fingerprint": entry.fingerprint,
                    "hashed": true,
                })
            }))
            .collect();
        let ca_json: Vec<serde_json::Value> = parsed
            .cert_authorities
            .iter()
            .map(|ca| {
                serde_json::json!({
                    "host_pattern": ca.host_pattern,
                    "fingerprint": ca.fingerprint,
                    "algorithm": ca.algorithm,
                })
            })
            .collect();
        let revoked_json: Vec<serde_json::Value> = parsed
            .revoked
            .iter()
            .map(|r| {
                serde_json::json!({
                    "host_pattern": r.host_pattern,
                    "fingerprint": r.fingerprint,
                })
            })
            .collect();
        let envelope = serde_json::json!({
            "metadata": {
                "tool": "gitway",
                "version": env!("CARGO_PKG_VERSION"),
                "command": "gitway hosts list",
                "timestamp": now_iso8601(),
            },
            "data": {
                "known_hosts_path": path.display().to_string(),
                "embedded": embedded_json,
                "direct": direct_json,
                "cert_authorities": ca_json,
                "revoked": revoked_json,
                "hashed_count": parsed.hashed.len(),
            },
        });
        emit_json(&envelope);
    } else {
        // Human format: four sections, three columns each.
        println!("# Embedded (built into anvil-ssh)");
        for (host, fp, alg) in &embedded {
            println!("{host:<24} {fp:<60} {alg}");
        }
        println!();
        println!("# User pins ({})", path.display());
        for entry in &parsed.direct {
            println!(
                "{host:<24} {fp:<60} direct",
                host = entry.host_pattern,
                fp = entry.fingerprint,
            );
        }
        for entry in &parsed.hashed {
            println!(
                "{host:<24} {fp:<60} direct",
                host = "(hashed)",
                fp = entry.fingerprint,
            );
        }
        println!();
        println!("# Cert authorities");
        for entry in &parsed.cert_authorities {
            println!(
                "{host:<24} {fp:<60} ca",
                host = entry.host_pattern,
                fp = entry.fingerprint,
            );
        }
        println!();
        println!("# Revoked");
        for entry in &parsed.revoked {
            println!(
                "{host:<24} {fp:<60} revoked",
                host = entry.host_pattern,
                fp = entry.fingerprint,
            );
        }
    }

    Ok(0)
}
