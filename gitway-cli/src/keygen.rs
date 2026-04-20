// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-21
//! Dispatcher for the `gitway keygen` subcommand tree.
//!
//! Maps parsed [`cli::KeygenSubcommand`] variants onto functions in
//! `gitway_lib::keygen`, `gitway_lib::sshsig`, and `gitway_lib::allowed_signers`.
//! All user-facing JSON/human output decisions live here; the library layer
//! stays output-agnostic.

use std::fs;
use std::io::{self, Write as _};
use std::path::Path;

use ssh_key::{HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use gitway_lib::GitwayError;
use gitway_lib::allowed_signers::AllowedSigners;
use gitway_lib::keygen::{self, KeyType};
use gitway_lib::sshsig;

use crate::cli::{
    ChangePassphraseArgs, ExtractPublicArgs, FingerprintArgs, GenerateArgs, HashKind, KeyAlg,
    KeygenSubcommand, VerifyArgs,
};
use crate::{OutputMode, emit_json, emit_json_line, now_iso8601, prompt_passphrase};

// ── Entry point ───────────────────────────────────────────────────────────────

/// Dispatches one `gitway keygen <sub>` invocation.
pub fn run(sub: KeygenSubcommand, mode: OutputMode) -> Result<u32, GitwayError> {
    match sub {
        KeygenSubcommand::Generate(args) => run_generate(args, mode),
        KeygenSubcommand::Fingerprint(args) => run_fingerprint(&args, mode),
        KeygenSubcommand::ExtractPublic(args) => run_extract_public(&args, mode),
        KeygenSubcommand::ChangePassphrase(args) => run_change_passphrase(args, mode),
        KeygenSubcommand::Sign(args) => super::sign::run(&args, mode),
        KeygenSubcommand::Verify(args) => run_verify(&args, mode),
    }
}

// ── generate ──────────────────────────────────────────────────────────────────

fn run_generate(args: GenerateArgs, mode: OutputMode) -> Result<u32, GitwayError> {
    let (kind, bits) = resolve_kind(args.kind, args.bits)?;
    let comment = args.comment.unwrap_or_else(default_comment);

    // Collect the passphrase up front (before spending cycles on generation)
    // so an early user abort does not waste key material.
    let passphrase = resolve_new_passphrase(&args.file, args.passphrase, args.no_passphrase)?;

    let key = keygen::generate(kind, bits, &comment)?;
    keygen::write_keypair(&key, &args.file, passphrase.as_ref())?;

    let fp = keygen::fingerprint(key.public_key(), HashAlg::Sha256);
    let pub_path = pub_path_for(&args.file);

    match mode {
        OutputMode::Json => {
            emit_json(&serde_json::json!({
                "metadata": {
                    "tool": "gitway",
                    "version": env!("CARGO_PKG_VERSION"),
                    "command": "gitway keygen generate",
                    "timestamp": now_iso8601(),
                },
                "data": {
                    "private_key_path": args.file,
                    "public_key_path": pub_path,
                    "algorithm": kind.cli_name(),
                    "encrypted": passphrase.is_some(),
                    "fingerprint": fp,
                    "comment": comment,
                }
            }));
        }
        OutputMode::Human => {
            eprintln!("gitway: generated {}", kind.cli_name());
            eprintln!("gitway: wrote {}", args.file.display());
            eprintln!("gitway: wrote {}", pub_path.display());
            eprintln!("gitway: fingerprint {fp}");
        }
    }
    Ok(0)
}

fn resolve_kind(alg: KeyAlg, bits: Option<u32>) -> Result<(KeyType, Option<u32>), GitwayError> {
    match alg {
        KeyAlg::Ed25519 => Ok((KeyType::Ed25519, None)),
        KeyAlg::Rsa => Ok((KeyType::Rsa, bits)),
        KeyAlg::Ecdsa => {
            let curve = bits.unwrap_or(DEFAULT_ECDSA_CURVE_BITS);
            match curve {
                256 => Ok((KeyType::EcdsaP256, None)),
                384 => Ok((KeyType::EcdsaP384, None)),
                521 => Ok((KeyType::EcdsaP521, None)),
                other => Err(GitwayError::invalid_config(format!(
                    "ECDSA curve size must be 256, 384, or 521 — got {other}"
                ))),
            }
        }
    }
}

/// Default ECDSA curve when `--bits` is omitted. 256 bits matches `ssh-keygen -t ecdsa`.
const DEFAULT_ECDSA_CURVE_BITS: u32 = 256;

// ── fingerprint ───────────────────────────────────────────────────────────────

fn run_fingerprint(args: &FingerprintArgs, mode: OutputMode) -> Result<u32, GitwayError> {
    let public = load_public_key(&args.file)?;
    let hash = hashkind_to_sshkey(args.hash);
    let fp = keygen::fingerprint(&public, hash);
    match mode {
        OutputMode::Json => {
            emit_json(&serde_json::json!({
                "metadata": {
                    "tool": "gitway",
                    "version": env!("CARGO_PKG_VERSION"),
                    "command": "gitway keygen fingerprint",
                    "timestamp": now_iso8601(),
                },
                "data": {
                    "path": args.file,
                    "fingerprint": fp,
                    "algorithm": public.algorithm().as_str(),
                    "comment": public.comment(),
                }
            }));
        }
        OutputMode::Human => {
            println!("{fp} {} {}", public.comment(), public.algorithm().as_str());
        }
    }
    Ok(0)
}

// ── extract-public ────────────────────────────────────────────────────────────

fn run_extract_public(args: &ExtractPublicArgs, mode: OutputMode) -> Result<u32, GitwayError> {
    keygen::extract_public(&args.file, args.output.as_deref())?;
    let out = args
        .output
        .clone()
        .unwrap_or_else(|| pub_path_for(&args.file));
    match mode {
        OutputMode::Json => {
            emit_json(&serde_json::json!({
                "metadata": {
                    "tool": "gitway",
                    "version": env!("CARGO_PKG_VERSION"),
                    "command": "gitway keygen extract-public",
                    "timestamp": now_iso8601(),
                },
                "data": {
                    "private_key_path": args.file,
                    "public_key_path": out,
                }
            }));
        }
        OutputMode::Human => {
            eprintln!("gitway: wrote {}", out.display());
        }
    }
    Ok(0)
}

// ── change-passphrase ─────────────────────────────────────────────────────────

fn run_change_passphrase(
    args: ChangePassphraseArgs,
    mode: OutputMode,
) -> Result<u32, GitwayError> {
    let pem = fs::read_to_string(&args.file)?;
    let loaded = PrivateKey::from_openssh(&pem)
        .map_err(|e| GitwayError::invalid_config(format!("cannot parse private key: {e}")))?;

    let old = if loaded.is_encrypted() {
        Some(match args.old_passphrase {
            Some(s) => Zeroizing::new(s),
            None => prompt_passphrase(&args.file)?,
        })
    } else {
        None
    };

    let new = if args.no_passphrase {
        None
    } else {
        Some(match args.new_passphrase {
            Some(s) => Zeroizing::new(s),
            None => prompt_new_passphrase(&args.file)?,
        })
    };

    keygen::change_passphrase(&args.file, old.as_ref(), new.as_ref())?;

    match mode {
        OutputMode::Json => {
            emit_json(&serde_json::json!({
                "metadata": {
                    "tool": "gitway",
                    "version": env!("CARGO_PKG_VERSION"),
                    "command": "gitway keygen change-passphrase",
                    "timestamp": now_iso8601(),
                },
                "data": {
                    "path": args.file,
                    "encrypted": new.is_some(),
                }
            }));
        }
        OutputMode::Human => {
            eprintln!("gitway: updated passphrase for {}", args.file.display());
        }
    }
    Ok(0)
}

// ── verify ────────────────────────────────────────────────────────────────────

fn run_verify(args: &VerifyArgs, mode: OutputMode) -> Result<u32, GitwayError> {
    let armored = fs::read_to_string(&args.signature)?;
    let allowed = AllowedSigners::load(&args.allowed_signers)?;

    let mut input = open_input(args.input.as_deref())?;
    let verified = sshsig::verify(
        &mut input,
        &armored,
        &args.signer,
        &args.namespace,
        &allowed,
    )?;

    match mode {
        OutputMode::Json => {
            emit_json(&serde_json::json!({
                "metadata": {
                    "tool": "gitway",
                    "version": env!("CARGO_PKG_VERSION"),
                    "command": "gitway keygen verify",
                    "timestamp": now_iso8601(),
                },
                "data": {
                    "verified": true,
                    "signer": verified.principal,
                    "fingerprint": verified.fingerprint,
                    "namespace": args.namespace,
                }
            }));
        }
        OutputMode::Human => {
            // Match ssh-keygen's "Good 'git' signature for <signer>" line so
            // downstream tools (git log --show-signature) can parse it.
            emit_json_line(&format!(
                "Good \"{}\" signature for {} with {} key {}",
                args.namespace, verified.principal, "ssh", verified.fingerprint
            ));
        }
    }
    Ok(0)
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Loads a public key from `path`, accepting either a `.pub` file or a
/// private key (from which the public key is derived).
fn load_public_key(path: &Path) -> Result<PublicKey, GitwayError> {
    let raw = fs::read_to_string(path)?;
    // Try public first (fastest path), then fall back to private.
    if let Ok(pk) = PublicKey::from_openssh(raw.trim()) {
        return Ok(pk);
    }
    match PrivateKey::from_openssh(&raw) {
        Ok(sk) => Ok(sk.public_key().clone()),
        Err(e) => Err(GitwayError::invalid_config(format!(
            "cannot parse key at {}: {e}",
            path.display()
        ))),
    }
}

fn pub_path_for(path: &Path) -> std::path::PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(".pub");
    std::path::PathBuf::from(os)
}

fn default_comment() -> String {
    // Mirror ssh-keygen's default "user@host" comment — best-effort on any
    // platform.
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".to_owned());
    let host = hostname();
    format!("{user}@{host}")
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "localhost".to_owned())
}

/// Resolves the passphrase for a newly generated key: command-line flag,
/// `--no-passphrase` escape hatch, or an interactive prompt.
fn resolve_new_passphrase(
    file: &Path,
    explicit: Option<String>,
    no_passphrase: bool,
) -> Result<Option<Zeroizing<String>>, GitwayError> {
    if no_passphrase {
        return Ok(None);
    }
    if let Some(s) = explicit {
        if s.is_empty() {
            return Ok(None);
        }
        return Ok(Some(Zeroizing::new(s)));
    }
    // Interactive: prompt for new passphrase (+ confirmation).
    let pp = prompt_new_passphrase(file)?;
    if pp.is_empty() {
        return Ok(None);
    }
    Ok(Some(pp))
}

/// Prompts for a new passphrase with confirmation. Reusing
/// [`prompt_passphrase`] twice would accept an unconfirmed single entry; this
/// helper matches `ssh-keygen`'s UX.
fn prompt_new_passphrase(path: &Path) -> Result<Zeroizing<String>, GitwayError> {
    use std::io::IsTerminal as _;
    // Non-interactive context: fall back to single-shot prompt via
    // SSH_ASKPASS. `prompt_passphrase` already handles that.
    if !std::io::stderr().is_terminal() {
        return prompt_passphrase(path);
    }
    let first = rpassword::prompt_password(format!(
        "Enter new passphrase for {} (empty for none): ",
        path.display()
    ))
    .map(Zeroizing::new)
    .map_err(GitwayError::from)?;
    if first.is_empty() {
        return Ok(Zeroizing::new(String::new()));
    }
    let confirm = rpassword::prompt_password("Enter same passphrase again: ")
        .map(Zeroizing::new)
        .map_err(GitwayError::from)?;
    if *first != *confirm {
        return Err(GitwayError::invalid_config(
            "passphrases did not match — aborting",
        ));
    }
    Ok(first)
}

/// Opens either the named file or stdin for signing/verifying.
pub(crate) fn open_input(path: Option<&Path>) -> Result<Box<dyn io::Read>, GitwayError> {
    match path {
        Some(p) if p.as_os_str() == "-" => Ok(Box::new(io::stdin())),
        Some(p) => Ok(Box::new(fs::File::open(p)?)),
        None => Ok(Box::new(io::stdin())),
    }
}

/// Writes signature bytes to either the named file or stdout.
pub(crate) fn write_output(path: Option<&Path>, bytes: &[u8]) -> Result<(), GitwayError> {
    match path {
        Some(p) if p.as_os_str() == "-" => {
            let mut out = io::stdout().lock();
            out.write_all(bytes)?;
            out.flush()?;
            Ok(())
        }
        Some(p) => {
            fs::write(p, bytes)?;
            Ok(())
        }
        None => {
            let mut out = io::stdout().lock();
            out.write_all(bytes)?;
            out.flush()?;
            Ok(())
        }
    }
}

pub(crate) fn hashkind_to_sshkey(k: HashKind) -> HashAlg {
    match k {
        HashKind::Sha256 => HashAlg::Sha256,
        HashKind::Sha512 => HashAlg::Sha512,
    }
}
