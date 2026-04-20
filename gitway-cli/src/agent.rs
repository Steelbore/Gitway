// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-21
//! Dispatcher for the `gitway agent` subcommand tree.
//!
//! Unix-only — Windows named-pipe support is Phase 3 scope. The
//! `#[cfg(unix)]` gate lives at the module-import site in `main.rs`.
//!
//! Maps parsed [`cli::AgentSubcommand`] variants onto
//! [`gitway_lib::agent::client::Agent`] operations. All user-facing output
//! lives here; the library layer stays output-agnostic.

use std::fs;
use std::path::Path;
use std::time::Duration;

use ssh_key::{HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use gitway_lib::agent::client::Agent;
use gitway_lib::keygen::fingerprint;
use gitway_lib::GitwayError;

use crate::cli::{
    AgentAddArgs, AgentListArgs, AgentLockArgs, AgentRemoveArgs, AgentSubcommand, HashKind,
};
use crate::{emit_json, emit_json_line, now_iso8601, prompt_passphrase, OutputMode};

// ── Entry point ───────────────────────────────────────────────────────────────

/// Dispatches one `gitway agent <sub>` invocation.
pub fn run(sub: AgentSubcommand, mode: OutputMode) -> Result<u32, GitwayError> {
    match sub {
        AgentSubcommand::Add(args) => run_add(&args, mode),
        AgentSubcommand::List(args) => run_list(&args, mode),
        AgentSubcommand::Remove(args) => run_remove(&args, mode),
        AgentSubcommand::Lock(args) => run_lock(&args, mode, /* lock = */ true),
        AgentSubcommand::Unlock(args) => run_lock(&args, mode, /* lock = */ false),
    }
}

// ── add ───────────────────────────────────────────────────────────────────────

fn run_add(args: &AgentAddArgs, mode: OutputMode) -> Result<u32, GitwayError> {
    let paths = if args.files.is_empty() {
        default_key_paths()?
    } else {
        args.files.clone()
    };
    let mut agent = Agent::from_env()?;
    let lifetime = args.lifetime.map(Duration::from_secs);
    let mut added = Vec::<String>::with_capacity(paths.len());
    for path in &paths {
        let key = load_private_key(path)?;
        agent.add(&key, lifetime, args.confirm)?;
        added.push(path.display().to_string());
    }

    match mode {
        OutputMode::Json => {
            emit_json(&serde_json::json!({
                "metadata": {
                    "tool": "gitway",
                    "version": env!("CARGO_PKG_VERSION"),
                    "command": "gitway agent add",
                    "timestamp": now_iso8601(),
                },
                "data": {
                    "added": added,
                    "lifetime_seconds": args.lifetime,
                    "confirm": args.confirm,
                }
            }));
        }
        OutputMode::Human => {
            for p in &added {
                eprintln!("gitway: identity added: {p}");
            }
        }
    }
    Ok(0)
}

/// Default private-key paths in the order `ssh-add` uses when given no
/// arguments: ed25519, ecdsa, rsa under `~/.ssh/`.
fn default_key_paths() -> Result<Vec<std::path::PathBuf>, GitwayError> {
    let home =
        dirs::home_dir().ok_or_else(|| GitwayError::invalid_config("cannot determine $HOME"))?;
    let candidates = ["id_ed25519", "id_ecdsa", "id_rsa"];
    let found: Vec<_> = candidates
        .iter()
        .map(|name| home.join(".ssh").join(name))
        .filter(|p| p.exists())
        .collect();
    if found.is_empty() {
        return Err(GitwayError::no_key_found());
    }
    Ok(found)
}

/// Loads and (if necessary) decrypts a private key, prompting for the
/// passphrase via the shared `prompt_passphrase` helper.
fn load_private_key(path: &Path) -> Result<PrivateKey, GitwayError> {
    let pem = fs::read_to_string(path)?;
    let key = PrivateKey::from_openssh(&pem).map_err(|e| {
        GitwayError::invalid_config(format!("cannot parse {}: {e}", path.display()))
    })?;
    if !key.is_encrypted() {
        return Ok(key);
    }
    let pp: Zeroizing<String> = prompt_passphrase(path)?;
    key.decrypt(pp.as_bytes())
        .map_err(|e| GitwayError::signing(format!("failed to decrypt {}: {e}", path.display())))
}

// ── list ──────────────────────────────────────────────────────────────────────

fn run_list(args: &AgentListArgs, mode: OutputMode) -> Result<u32, GitwayError> {
    let mut agent = Agent::from_env()?;
    let ids = agent.list()?;
    let hash_alg = hashkind_to_sshkey(args.hash);

    match mode {
        OutputMode::Json => {
            emit_json(&serde_json::json!({
                "metadata": {
                    "tool": "gitway",
                    "version": env!("CARGO_PKG_VERSION"),
                    "command": "gitway agent list",
                    "timestamp": now_iso8601(),
                },
                "data": {
                    "identity_count": ids.len(),
                    "identities": ids.iter().map(|id| serde_json::json!({
                        "fingerprint": fingerprint(&id.public_key, hash_alg),
                        "algorithm": id.public_key.algorithm().as_str(),
                        "comment": id.comment,
                    })).collect::<Vec<_>>(),
                }
            }));
        }
        OutputMode::Human => {
            if ids.is_empty() {
                eprintln!("gitway: the agent has no identities");
            } else if args.full {
                for id in &ids {
                    let line = id.public_key.to_openssh().map_err(|e| {
                        GitwayError::signing(format!("failed to serialize public key: {e}"))
                    })?;
                    emit_json_line(&line);
                }
            } else {
                for id in &ids {
                    emit_json_line(&format!(
                        "{} {} ({})",
                        fingerprint(&id.public_key, hash_alg),
                        id.comment,
                        id.public_key.algorithm().as_str().to_uppercase(),
                    ));
                }
            }
        }
    }
    Ok(0)
}

// ── remove ────────────────────────────────────────────────────────────────────

fn run_remove(args: &AgentRemoveArgs, mode: OutputMode) -> Result<u32, GitwayError> {
    let mut agent = Agent::from_env()?;
    let removed: Vec<String>;
    if args.all {
        let ids = agent.list()?;
        agent.remove_all()?;
        removed = ids
            .iter()
            .map(|id| fingerprint(&id.public_key, HashAlg::Sha256))
            .collect();
    } else if let Some(ref path) = args.file {
        let pk = load_public_or_derive(path)?;
        agent.remove(&pk)?;
        removed = vec![fingerprint(&pk, HashAlg::Sha256)];
    } else {
        return Err(GitwayError::invalid_config(
            "`gitway agent remove` requires a <FILE> argument or `--all`",
        ));
    }

    match mode {
        OutputMode::Json => {
            emit_json(&serde_json::json!({
                "metadata": {
                    "tool": "gitway",
                    "version": env!("CARGO_PKG_VERSION"),
                    "command": "gitway agent remove",
                    "timestamp": now_iso8601(),
                },
                "data": {
                    "removed": removed,
                    "all": args.all,
                }
            }));
        }
        OutputMode::Human => {
            for fp in &removed {
                eprintln!("gitway: identity removed: {fp}");
            }
        }
    }
    Ok(0)
}

/// Loads a public key from `path`, accepting either a `.pub` file or a
/// private key (from which the public key is derived).
fn load_public_or_derive(path: &Path) -> Result<PublicKey, GitwayError> {
    let raw = fs::read_to_string(path)?;
    if let Ok(pk) = PublicKey::from_openssh(raw.trim()) {
        return Ok(pk);
    }
    match PrivateKey::from_openssh(&raw) {
        Ok(sk) => Ok(sk.public_key().clone()),
        Err(e) => Err(GitwayError::invalid_config(format!(
            "cannot parse {}: {e}",
            path.display()
        ))),
    }
}

// ── lock / unlock ─────────────────────────────────────────────────────────────

fn run_lock(args: &AgentLockArgs, mode: OutputMode, lock: bool) -> Result<u32, GitwayError> {
    let mut agent = Agent::from_env()?;
    let pp: Zeroizing<String> = match &args.passphrase {
        Some(s) => Zeroizing::new(s.clone()),
        None => prompt_lock_passphrase(lock)?,
    };
    if lock {
        agent.lock(&pp)?;
    } else {
        agent.unlock(&pp)?;
    }

    let verb = if lock { "locked" } else { "unlocked" };
    match mode {
        OutputMode::Json => {
            emit_json(&serde_json::json!({
                "metadata": {
                    "tool": "gitway",
                    "version": env!("CARGO_PKG_VERSION"),
                    "command": format!("gitway agent {verb}"),
                    "timestamp": now_iso8601(),
                },
                "data": {
                    "state": verb,
                }
            }));
        }
        OutputMode::Human => {
            eprintln!("gitway: agent {verb}");
        }
    }
    Ok(0)
}

/// Interactive prompt used when `--passphrase` is omitted. Lock requires
/// confirmation; unlock is a single entry.
fn prompt_lock_passphrase(lock: bool) -> Result<Zeroizing<String>, GitwayError> {
    if lock {
        let first = rpassword::prompt_password("Agent lock passphrase: ")
            .map(Zeroizing::new)
            .map_err(GitwayError::from)?;
        let confirm = rpassword::prompt_password("Confirm lock passphrase: ")
            .map(Zeroizing::new)
            .map_err(GitwayError::from)?;
        if *first != *confirm {
            return Err(GitwayError::invalid_config(
                "passphrases did not match — aborting",
            ));
        }
        Ok(first)
    } else {
        rpassword::prompt_password("Agent unlock passphrase: ")
            .map(Zeroizing::new)
            .map_err(GitwayError::from)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hashkind_to_sshkey(k: HashKind) -> HashAlg {
    match k {
        HashKind::Sha256 => HashAlg::Sha256,
        HashKind::Sha512 => HashAlg::Sha512,
    }
}
