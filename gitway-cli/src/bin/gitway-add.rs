// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-21
// S3: enforce zero unsafe in all project-owned code at compile time.
#![forbid(unsafe_code)]
//! `gitway-add` — drop-in replacement for the subset of `ssh-add` that
//! shells out by name (IDE integrations, git-credential-manager,
//! systemd user units, etc.).
//!
//! ## Supported argv surface
//!
//! | Flag | Purpose |
//! |------|---------|
//! | `-l` | List loaded fingerprints (default when no files given) |
//! | `-L` | List full public keys |
//! | `-d <file>` | Remove a specific identity |
//! | `-D` | Remove all identities |
//! | `-x` | Lock the agent with a passphrase |
//! | `-X` | Unlock the agent |
//! | `-t <seconds>` | Lifetime for subsequently-added keys |
//! | `-E <sha256\|sha512>` | Fingerprint hash for `-l` |
//! | `-c` | Ask for confirmation on each sign |
//! | `<file>...` | Add these private keys (default: `~/.ssh/id_ed25519`) |
//!
//! Unsupported ssh-add flags are silently ignored for compatibility.
//!
//! ## Platform support
//!
//! Unix-only. The agent protocol in Phase 2 only speaks over Unix domain
//! sockets; Windows named-pipe support lands in Phase 3 (v0.6) alongside
//! the agent daemon. On Windows, the binary still builds but exits with
//! code 2 and a pointer to the upcoming release.

// Cross-platform stub: on Windows the binary links cleanly but explains
// the limitation and exits non-zero, so packaging can still produce it
// as an artifact if desired.
#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "gitway-add: not supported on this platform. \
         Unix-only in v0.5; Windows support lands in v0.6 \
         with the agent daemon (named-pipe transport)."
    );
    std::process::ExitCode::from(2)
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    unix::main()
}

// Everything that actually does work lives under this `mod unix` gate so
// the imports and types don't fail to resolve on non-Unix targets.
#[cfg(unix)]
mod unix {

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use ssh_key::{HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use gitway_lib::agent::client::Agent;
use gitway_lib::keygen::fingerprint;
use gitway_lib::GitwayError;

// ── Main ──────────────────────────────────────────────────────────────────────

pub fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(e) => {
            eprintln!("gitway-add: error: {e}");
            ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(1))
        }
    }
}

fn run(args: &[String]) -> Result<u32, GitwayError> {
    let parsed = Parsed::from_args(args)?;
    let mut agent = Agent::from_env()?;

    match parsed.mode {
        Mode::List { full } => list(&mut agent, full, parsed.hash),
        Mode::RemoveOne { path } => remove_one(&mut agent, &path),
        Mode::RemoveAll => remove_all(&mut agent),
        Mode::Lock => lock_unlock(&mut agent, /* lock = */ true),
        Mode::Unlock => lock_unlock(&mut agent, /* lock = */ false),
        Mode::Add { paths } => add(&mut agent, &paths, parsed.lifetime, parsed.confirm),
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum Mode {
    List { full: bool },
    RemoveOne { path: PathBuf },
    RemoveAll,
    Lock,
    Unlock,
    Add { paths: Vec<PathBuf> },
}

#[derive(Debug)]
struct Parsed {
    mode: Mode,
    hash: HashAlg,
    lifetime: Option<Duration>,
    confirm: bool,
}

impl Parsed {
    fn from_args(args: &[String]) -> Result<Self, GitwayError> {
        let mut hash = HashAlg::Sha256;
        let mut lifetime: Option<Duration> = None;
        let mut confirm = false;

        let mut mode: Option<Mode> = None;
        let mut paths: Vec<PathBuf> = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            match a.as_str() {
                "-l" => {
                    set_mode(&mut mode, Mode::List { full: false }, "-l")?;
                    i += 1;
                }
                "-L" => {
                    set_mode(&mut mode, Mode::List { full: true }, "-L")?;
                    i += 1;
                }
                "-D" => {
                    set_mode(&mut mode, Mode::RemoveAll, "-D")?;
                    i += 1;
                }
                "-x" => {
                    set_mode(&mut mode, Mode::Lock, "-x")?;
                    i += 1;
                }
                "-X" => {
                    set_mode(&mut mode, Mode::Unlock, "-X")?;
                    i += 1;
                }
                "-c" => {
                    confirm = true;
                    i += 1;
                }
                "-d" => {
                    // `take` already advances `i` past both the flag and its value.
                    let path = take(args, &mut i, "-d")?;
                    set_mode(&mut mode, Mode::RemoveOne { path: path.into() }, "-d")?;
                }
                "-t" => {
                    let secs = take(args, &mut i, "-t")?;
                    let n: u64 = secs.parse().map_err(|_e: std::num::ParseIntError| {
                        GitwayError::invalid_config(format!(
                            "-t requires an integer number of seconds, got {secs:?}"
                        ))
                    })?;
                    lifetime = Some(Duration::from_secs(n));
                }
                "-E" => {
                    let v = take(args, &mut i, "-E")?;
                    hash = match v.to_ascii_lowercase().as_str() {
                        "sha256" => HashAlg::Sha256,
                        "sha512" => HashAlg::Sha512,
                        other => {
                            return Err(GitwayError::invalid_config(format!(
                                "-E requires sha256 or sha512, got {other:?}"
                            )));
                        }
                    };
                }
                // Silently-ignored ssh-add flags we do not implement yet.
                // (These are non-fatal for the CI/IDE integration use
                // case; behaviour diverges from real ssh-add when the
                // flag carries semantic meaning.)
                "-q" | "-v" | "-vv" | "-vvv" | "-H" | "-T" | "-s" | "-S" | "-e" | "-k" => {
                    i += 1;
                }
                "--" => {
                    i += 1;
                    // Everything after `--` is a positional path.
                    while i < args.len() {
                        paths.push(PathBuf::from(&args[i]));
                        i += 1;
                    }
                }
                other if other.starts_with('-') => {
                    return Err(GitwayError::invalid_config(format!(
                        "unsupported flag: {other}"
                    )));
                }
                _ => {
                    paths.push(PathBuf::from(a));
                    i += 1;
                }
            }
        }

        // Default when no mode-selecting flag was given.
        let mode = match mode {
            Some(m) => m,
            None if paths.is_empty() => Mode::Add {
                paths: default_key_paths()?,
            },
            None => Mode::Add { paths },
        };

        Ok(Self {
            mode,
            hash,
            lifetime,
            confirm,
        })
    }
}

fn set_mode(slot: &mut Option<Mode>, new: Mode, flag: &str) -> Result<(), GitwayError> {
    if slot.is_some() {
        return Err(GitwayError::invalid_config(format!(
            "{flag} conflicts with a previous mode flag"
        )));
    }
    *slot = Some(new);
    Ok(())
}

fn take(args: &[String], i: &mut usize, flag: &str) -> Result<String, GitwayError> {
    *i += 1;
    let v = args
        .get(*i)
        .cloned()
        .ok_or_else(|| GitwayError::invalid_config(format!("{flag} requires a value")))?;
    *i += 1;
    Ok(v)
}

// ── Operations ────────────────────────────────────────────────────────────────

fn list(agent: &mut Agent, full: bool, hash: HashAlg) -> Result<u32, GitwayError> {
    let ids = agent.list()?;
    if ids.is_empty() {
        println!("The agent has no identities.");
        return Ok(1);
    }
    for id in &ids {
        if full {
            let line = id
                .public_key
                .to_openssh()
                .map_err(|e| GitwayError::signing(format!("serialize failed: {e}")))?;
            println!("{line}");
        } else {
            println!(
                "{} {} ({})",
                fingerprint(&id.public_key, hash),
                id.comment,
                id.public_key.algorithm().as_str().to_uppercase(),
            );
        }
    }
    Ok(0)
}

fn remove_one(agent: &mut Agent, path: &Path) -> Result<u32, GitwayError> {
    let raw = fs::read_to_string(path)?;
    let public_key = PublicKey::from_openssh(raw.trim())
        .or_else(|_| PrivateKey::from_openssh(&raw).map(|sk| sk.public_key().clone()))
        .map_err(|e| {
            GitwayError::invalid_config(format!("cannot parse {}: {e}", path.display()))
        })?;
    agent.remove(&public_key)?;
    println!(
        "Identity removed: {}",
        fingerprint(&public_key, HashAlg::Sha256)
    );
    Ok(0)
}

fn remove_all(agent: &mut Agent) -> Result<u32, GitwayError> {
    agent.remove_all()?;
    println!("All identities removed.");
    Ok(0)
}

fn lock_unlock(agent: &mut Agent, lock: bool) -> Result<u32, GitwayError> {
    let pp = if lock {
        let first = rpassword::prompt_password("Enter lock passphrase: ")
            .map(Zeroizing::new)
            .map_err(GitwayError::from)?;
        let confirm = rpassword::prompt_password("Confirm lock passphrase: ")
            .map(Zeroizing::new)
            .map_err(GitwayError::from)?;
        if *first != *confirm {
            return Err(GitwayError::invalid_config("passphrases did not match"));
        }
        first
    } else {
        rpassword::prompt_password("Enter unlock passphrase: ")
            .map(Zeroizing::new)
            .map_err(GitwayError::from)?
    };

    if lock {
        agent.lock(&pp)?;
        println!("Agent locked.");
    } else {
        agent.unlock(&pp)?;
        println!("Agent unlocked.");
    }
    Ok(0)
}

fn add(
    agent: &mut Agent,
    paths: &[PathBuf],
    lifetime: Option<Duration>,
    confirm: bool,
) -> Result<u32, GitwayError> {
    for path in paths {
        let key = load_and_decrypt(path)?;
        agent.add(&key, lifetime, confirm)?;
        println!("Identity added: {}", path.display());
    }
    Ok(0)
}

fn load_and_decrypt(path: &Path) -> Result<PrivateKey, GitwayError> {
    let pem = fs::read_to_string(path)?;
    let key = PrivateKey::from_openssh(&pem).map_err(|e| {
        GitwayError::invalid_config(format!("cannot parse {}: {e}", path.display()))
    })?;
    if !key.is_encrypted() {
        return Ok(key);
    }
    let pp: Zeroizing<String> = if let Some(from_stdin) = passphrase_from_stdin_if_not_tty() {
        from_stdin
    } else {
        rpassword::prompt_password(format!("Enter passphrase for {}: ", path.display()))
            .map(Zeroizing::new)
            .map_err(GitwayError::from)?
    };
    key.decrypt(pp.as_bytes())
        .map_err(|e| GitwayError::signing(format!("decrypt failed: {e}")))
}

/// When stdin is not a terminal (e.g. the shim is invoked from a script),
/// reading a passphrase from a TTY prompt can fail with ENXIO.  Fall back
/// to reading one line from stdin — matches `ssh-add`'s `-p` / piped-input
/// behaviour without actually implementing `-p`.
fn passphrase_from_stdin_if_not_tty() -> Option<Zeroizing<String>> {
    use std::io::IsTerminal as _;
    if std::io::stdin().is_terminal() {
        return None;
    }
    let mut s = String::new();
    if std::io::stdin().read_to_string(&mut s).is_err() {
        return None;
    }
    // Trim a single trailing newline, like rpassword does.
    let trimmed = s.trim_end_matches('\n').to_owned();
    Some(Zeroizing::new(trimmed))
}

fn default_key_paths() -> Result<Vec<PathBuf>, GitwayError> {
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

} // mod unix
