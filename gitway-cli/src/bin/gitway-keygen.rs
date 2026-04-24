// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-21
// S3: enforce zero unsafe in all project-owned code at compile time.
#![forbid(unsafe_code)]
//! `gitway-keygen` — drop-in replacement for the subset of `ssh-keygen`
//! that git invokes when `gpg.format=ssh` and `gpg.ssh.program=gitway-keygen`.
//!
//! This binary is deliberately separate from the main `gitway` CLI:
//!
//! - Git parses `ssh-keygen`'s stdout byte-for-byte (e.g. `"Good \"git\"
//!   signature..."`); a clap-based wrapper would risk drift from the
//!   expected format.
//! - `gitway keygen ...` exposes the ergonomic Gitway-native UX with
//!   subcommand verbs and `--json`. This shim exposes only the
//!   ssh-keygen flag surface.
//!
//! ## Supported flags
//!
//! | Flag | Purpose |
//! |------|---------|
//! | `-t TYPE` | Algorithm (`ed25519` \| `ecdsa` \| `rsa`) |
//! | `-b BITS` | RSA size or ECDSA curve |
//! | `-f FILE` | Output / input key path |
//! | `-N PP` | New passphrase (empty string = unencrypted) |
//! | `-P PP` | Old passphrase |
//! | `-C CMT` | Comment |
//! | `-l` | Print fingerprint of `-f FILE` |
//! | `-y` | Print public key from private key at `-f FILE` |
//! | `-p` | Change passphrase of key at `-f FILE` |
//! | `-E HASH` | Fingerprint hash: `sha256` \| `sha512` |
//! | `-Y sign` | Produce SSHSIG on stdin → stdout |
//! | `-Y verify` | Verify SSHSIG against allowed-signers |
//! | `-Y check-novalidate` | Verify SSHSIG shape only |
//! | `-Y find-principals` | Find principals in allowed-signers for SSHSIG |
//! | `-n NAMESPACE` | SSHSIG namespace |
//! | `-I IDENTITY` | Signer identity for verify |
//! | `-s SIG` | Signature file for verify |

use std::env;
use std::fs;
use std::io::{self, Cursor, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use gitway_lib::agent::client::Agent;
use gitway_lib::allowed_signers::AllowedSigners;
use gitway_lib::keygen::{self, KeyType};
use gitway_lib::sshsig;
use gitway_lib::GitwayError;

// ── Top-level dispatch ────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => {
            let byte = u8::try_from(code).unwrap_or(1);
            ExitCode::from(byte)
        }
        Err(e) => {
            eprintln!("gitway-keygen: error: {e}");
            // Single-line diagnostic — git invokes this shim via
            // `gpg.ssh.program` and treats any non-zero exit as "signing
            // failed" with no further context, so emit one grep-able
            // record to stderr (stdout stays byte-compatible with
            // ssh-keygen for git's parser).
            gitway_lib::diagnostic::emit_for(&e);
            let byte = u8::try_from(e.exit_code()).unwrap_or(1);
            ExitCode::from(byte)
        }
    }
}

fn run(args: &[String]) -> Result<u32, GitwayError> {
    let parsed = Parsed::from_args(args)?;
    match parsed.mode {
        Mode::GenerateKey => run_generate(&parsed),
        Mode::PrintFingerprint => run_fingerprint(&parsed),
        Mode::ExtractPublic => run_extract_public(&parsed),
        Mode::ChangePassphrase => run_change_passphrase(&parsed),
        Mode::SshSigSign => run_sign(&parsed),
        Mode::SshSigVerify => run_verify(&parsed),
        Mode::SshSigCheckNoValidate => run_check_novalidate(&parsed),
        Mode::SshSigFindPrincipals => run_find_principals(&parsed),
    }
}

// ── Mode enum ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    GenerateKey,
    PrintFingerprint,
    ExtractPublic,
    ChangePassphrase,
    SshSigSign,
    SshSigVerify,
    SshSigCheckNoValidate,
    SshSigFindPrincipals,
}

// ── Parser ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Parsed {
    mode: Mode,
    key_type: Option<String>,
    bits: Option<u32>,
    file: Option<PathBuf>,
    new_passphrase: Option<String>,
    old_passphrase: Option<String>,
    comment: Option<String>,
    namespace: Option<String>,
    signer_identity: Option<String>,
    signature_file: Option<PathBuf>,
    allowed_signers: Option<PathBuf>,
    fingerprint_hash: HashAlg,
    /// Positional file argument — the data file for `-Y sign`. Git's SSH
    /// signing path uses this form: `ssh-keygen -Y sign -n git -f <key>
    /// <messagefile>` and expects the signature at `<messagefile>.sig`.
    message_file: Option<PathBuf>,
}

impl Parsed {
    #[expect(
        clippy::too_many_lines,
        reason = "flag parser is intentionally a flat argv loop — splitting \
                  it across helper fns would obscure the match-on-flag-name \
                  structure that mirrors ssh-keygen's own argv handling."
    )]
    fn from_args(args: &[String]) -> Result<Self, GitwayError> {
        let mut p = Self {
            mode: Mode::GenerateKey,
            key_type: None,
            bits: None,
            file: None,
            new_passphrase: None,
            old_passphrase: None,
            comment: None,
            namespace: None,
            signer_identity: None,
            signature_file: None,
            allowed_signers: None,
            fingerprint_hash: HashAlg::Sha256,
            message_file: None,
        };

        let mut saw_list = false;
        let mut saw_extract = false;
        let mut saw_change = false;
        let mut sshsig_op: Option<String> = None;

        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            match a.as_str() {
                "-t" => p.key_type = Some(take_value(args, &mut i, "-t")?),
                "-b" => {
                    let v = take_value(args, &mut i, "-b")?;
                    p.bits = Some(v.parse().map_err(|_e: std::num::ParseIntError| {
                        GitwayError::invalid_config(format!("-b requires an integer, got {v:?}"))
                    })?);
                }
                "-f" => p.file = Some(PathBuf::from(take_value(args, &mut i, "-f")?)),
                "-N" => p.new_passphrase = Some(take_value(args, &mut i, "-N")?),
                "-P" => p.old_passphrase = Some(take_value(args, &mut i, "-P")?),
                "-C" => p.comment = Some(take_value(args, &mut i, "-C")?),
                "-n" => p.namespace = Some(take_value(args, &mut i, "-n")?),
                "-I" => p.signer_identity = Some(take_value(args, &mut i, "-I")?),
                "-s" => p.signature_file = Some(PathBuf::from(take_value(args, &mut i, "-s")?)),
                "-l" => {
                    saw_list = true;
                    i += 1;
                }
                "-y" => {
                    saw_extract = true;
                    i += 1;
                }
                "-p" => {
                    saw_change = true;
                    i += 1;
                }
                "-E" => {
                    let v = take_value(args, &mut i, "-E")?;
                    p.fingerprint_hash = match v.to_ascii_lowercase().as_str() {
                        "sha256" => HashAlg::Sha256,
                        "sha512" => HashAlg::Sha512,
                        other => {
                            return Err(GitwayError::invalid_config(format!(
                                "-E requires sha256 or sha512, got {other:?}"
                            )));
                        }
                    };
                }
                "-Y" => {
                    sshsig_op = Some(take_value(args, &mut i, "-Y")?);
                }
                "--allowed-signers" => {
                    p.allowed_signers = Some(PathBuf::from(take_value(
                        args,
                        &mut i,
                        "--allowed-signers",
                    )?));
                }
                "-O" => {
                    // Option pass-through used by `ssh-keygen -Y sign`: we
                    // accept and ignore (the only upstream option we might
                    // care about is `hashalg=...` which the SSHSIG layer
                    // picks its own default for).
                    let _ = take_value(args, &mut i, "-O")?;
                }
                "-q" | "-v" | "-vv" | "-vvv" => {
                    // Quiet / verbose flags accepted for compat; ignored.
                    i += 1;
                }
                "--" => {
                    break;
                }
                other if other.starts_with('-') => {
                    return Err(GitwayError::invalid_config(format!(
                        "unsupported flag: {other}"
                    )));
                }
                _ => {
                    // Bare positional — the message file for `-Y sign`
                    // (git's SSH signing path uses this form). If `-f`
                    // is absent entirely, the positional seeds it as a
                    // last-ditch input (older ssh-keygen releases).
                    if p.message_file.is_none() {
                        p.message_file = Some(PathBuf::from(a));
                    } else if p.file.is_none() {
                        p.file = Some(PathBuf::from(a));
                    }
                    i += 1;
                }
            }
        }

        if let Some(op) = sshsig_op.as_deref() {
            p.mode = match op {
                "sign" => Mode::SshSigSign,
                "verify" => Mode::SshSigVerify,
                "check-novalidate" => Mode::SshSigCheckNoValidate,
                "find-principals" => Mode::SshSigFindPrincipals,
                other => {
                    return Err(GitwayError::invalid_config(format!(
                        "-Y requires sign|verify|check-novalidate|find-principals, got {other:?}"
                    )));
                }
            };
        } else if saw_list {
            p.mode = Mode::PrintFingerprint;
        } else if saw_extract {
            p.mode = Mode::ExtractPublic;
        } else if saw_change {
            p.mode = Mode::ChangePassphrase;
        } else {
            p.mode = Mode::GenerateKey;
        }
        Ok(p)
    }
}

fn take_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, GitwayError> {
    *i += 1;
    let v = args
        .get(*i)
        .cloned()
        .ok_or_else(|| GitwayError::invalid_config(format!("{flag} requires a value")))?;
    *i += 1;
    Ok(v)
}

// ── Subcommand bodies ─────────────────────────────────────────────────────────

fn run_generate(p: &Parsed) -> Result<u32, GitwayError> {
    let Some(file) = p.file.clone() else {
        return Err(GitwayError::invalid_config("-f FILE is required"));
    };
    let kind = parse_kind(p.key_type.as_deref().unwrap_or("ed25519"), p.bits)?;
    let comment = p.comment.clone().unwrap_or_else(default_comment);

    // `-N ""` means "generate an unencrypted key" — the historical
    // ssh-keygen behaviour. `-N` omitted means "prompt interactively",
    // which we approximate with a single rpassword call.
    let passphrase: Option<Zeroizing<String>> = match &p.new_passphrase {
        Some(s) if s.is_empty() => None,
        Some(s) => Some(Zeroizing::new(s.clone())),
        None => {
            let pp = rpassword::prompt_password(format!(
                "Enter passphrase (empty for none) for {}: ",
                file.display()
            ))
            .map(Zeroizing::new)
            .map_err(GitwayError::from)?;
            if pp.is_empty() {
                None
            } else {
                Some(pp)
            }
        }
    };

    let key = keygen::generate(kind, p.bits, &comment)?;
    keygen::write_keypair(&key, &file, passphrase.as_ref())?;

    // ssh-keygen prints:
    //   Your identification has been saved in <file>
    //   Your public key has been saved in <file>.pub
    //   The key fingerprint is: SHA256:... user@host
    let pub_path = format!("{}.pub", file.display());
    println!("Your identification has been saved in {}", file.display());
    println!("Your public key has been saved in {pub_path}");
    let fp = keygen::fingerprint(key.public_key(), HashAlg::Sha256);
    println!("The key fingerprint is:");
    println!("{fp} {comment}");
    Ok(0)
}

fn run_fingerprint(p: &Parsed) -> Result<u32, GitwayError> {
    let Some(file) = p.file.clone() else {
        return Err(GitwayError::invalid_config("-f FILE is required"));
    };
    let public = load_public_key(&file)?;
    let fp = keygen::fingerprint(&public, p.fingerprint_hash);
    // ssh-keygen -l format: "<bits> <fingerprint> <comment> (<algorithm>)"
    let bits = public_bit_estimate(&public);
    println!(
        "{bits} {fp} {} ({})",
        public.comment(),
        public.algorithm().as_str().to_uppercase()
    );
    Ok(0)
}

fn run_extract_public(p: &Parsed) -> Result<u32, GitwayError> {
    let Some(file) = p.file.clone() else {
        return Err(GitwayError::invalid_config("-f FILE is required"));
    };
    let pem = fs::read_to_string(&file)?;
    let mut key = PrivateKey::from_openssh(&pem)
        .map_err(|e| GitwayError::invalid_config(format!("cannot parse key: {e}")))?;
    if key.is_encrypted() {
        let pp: Zeroizing<String> = match &p.old_passphrase {
            Some(s) => Zeroizing::new(s.clone()),
            None => {
                rpassword::prompt_password(format!("Enter passphrase for {}: ", file.display()))
                    .map(Zeroizing::new)
                    .map_err(GitwayError::from)?
            }
        };
        key = key
            .decrypt(pp.as_bytes())
            .map_err(|e| GitwayError::signing(format!("decrypt failed: {e}")))?;
    }
    let public_line = key
        .public_key()
        .to_openssh()
        .map_err(|e| GitwayError::signing(format!("serialize failed: {e}")))?;
    // ssh-keygen -y writes to stdout with a trailing newline.
    let mut out = io::stdout().lock();
    writeln!(out, "{public_line}")?;
    Ok(0)
}

fn run_change_passphrase(p: &Parsed) -> Result<u32, GitwayError> {
    let Some(file) = p.file.clone() else {
        return Err(GitwayError::invalid_config("-f FILE is required"));
    };
    let old = if let Some(s) = &p.old_passphrase {
        Some(Zeroizing::new(s.clone()))
    } else {
        Some(
            rpassword::prompt_password(format!("Enter old passphrase for {}: ", file.display()))
                .map(Zeroizing::new)
                .map_err(GitwayError::from)?,
        )
    };
    let new = match &p.new_passphrase {
        Some(s) if s.is_empty() => None,
        Some(s) => Some(Zeroizing::new(s.clone())),
        None => {
            let pp = rpassword::prompt_password("Enter new passphrase (empty for none): ")
                .map(Zeroizing::new)
                .map_err(GitwayError::from)?;
            if pp.is_empty() {
                None
            } else {
                Some(pp)
            }
        }
    };
    keygen::change_passphrase(&file, old.as_ref(), new.as_ref())?;
    println!("Your identification has been saved with the new passphrase.");
    Ok(0)
}

fn run_sign(p: &Parsed) -> Result<u32, GitwayError> {
    let Some(file) = p.file.clone() else {
        return Err(GitwayError::invalid_config(
            "-f FILE is required for -Y sign",
        ));
    };
    let Some(ns) = p.namespace.clone() else {
        return Err(GitwayError::invalid_config(
            "-n NAMESPACE is required for -Y sign",
        ));
    };

    // Two input modes — mirrors ssh-keygen(1):
    //
    //  (a) `ssh-keygen -Y sign -n git -f <key>` reads the message from
    //      stdin and writes the armored signature to stdout.
    //  (b) `ssh-keygen -Y sign -n git -f <key> <messagefile>` reads the
    //      message from <messagefile> and writes the signature to
    //      <messagefile>.sig (overwriting if present).
    //
    // Git's `sign_buffer_ssh` (gpg-interface.c) uses form (b).
    let (data, sig_out): (Vec<u8>, Option<PathBuf>) = if let Some(msg) = p.message_file.clone() {
        let bytes = fs::read(&msg)?;
        let mut out = msg.as_os_str().to_owned();
        out.push(".sig");
        (bytes, Some(PathBuf::from(out)))
    } else {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        (bytes, None)
    };

    // Try the agent path first: if `SSH_AUTH_SOCK` is set, the socket
    // is reachable, and the agent holds the matching private key, sign
    // via the agent and return.  This path never reads the private-key
    // file and therefore never prompts for a passphrase — the common
    // failure mode for git-invoked `gitway-keygen` in non-interactive
    // contexts (IDE, systemd service, CI) where stdin is not a TTY.
    if let Some(armored) = try_sign_via_agent(&file, &data, &ns)? {
        return write_sig_output(armored.as_bytes(), sig_out.as_deref());
    }

    // Fall back to the direct-read path.  Git passes `user.signingkey`
    // to `-f`, usually the `.pub` path; `resolve_signing_key_path`
    // strips `.pub` to find the private key.
    let key_file = resolve_signing_key_path(&file)?;
    let key = load_and_decrypt(&key_file, p.old_passphrase.as_deref())?;

    let sig = ssh_key::SshSig::sign(&key, &ns, HashAlg::Sha512, &data)
        .map_err(|e| GitwayError::signing(format!("sshsig sign failed: {e}")))?;
    let armored = sig
        .to_pem(LineEnding::LF)
        .map_err(|e| GitwayError::signing(format!("armor failed: {e}")))?;

    write_sig_output(armored.as_bytes(), sig_out.as_deref())
}

/// Tries to sign `data` via the SSH agent at `$SSH_AUTH_SOCK`.
///
/// Returns `Ok(Some(armored))` on a successful agent sign, `Ok(None)`
/// when the agent path is not usable (env var unset, socket gone, key
/// not loaded) — caller should fall back to the direct-read path.
/// Returns `Err(_)` only for genuine errors *after* we've committed to
/// the agent (e.g. the agent had our key but the sign request was
/// actively denied via `--confirm`).
fn try_sign_via_agent(
    key_path: &Path,
    data: &[u8],
    namespace: &str,
) -> Result<Option<String>, GitwayError> {
    if env::var_os("SSH_AUTH_SOCK").is_none_or(|v| v.is_empty()) {
        return Ok(None);
    }
    let Ok(pubkey) = load_public_key_for_signing(key_path) else {
        return Ok(None);
    };
    let Ok(mut agent) = Agent::from_env() else {
        return Ok(None);
    };
    let Ok(identities) = agent.list() else {
        return Ok(None);
    };
    let want = pubkey.fingerprint(HashAlg::Sha256).to_string();
    if !identities.iter().any(|id| id.fingerprint == want) {
        return Ok(None);
    }
    let mut cursor = Cursor::new(data);
    let armored =
        sshsig::sign_with_agent(&mut cursor, &mut agent, &pubkey, namespace, HashAlg::Sha512)?;
    Ok(Some(armored))
}

/// Reads the public key at `path` without touching private-key
/// material.
///
/// Accepts both forms of `-f` argument:
///
///  - a `.pub` file (what git usually passes for `gpg.ssh.program`) —
///    parsed directly as `PublicKey::from_openssh`;
///  - a private-key file, encrypted or not — `PrivateKey::from_openssh`
///    parses the plaintext public-key portion even when the private
///    bytes are still encrypted, so we extract the public key without
///    needing the passphrase.
fn load_public_key_for_signing(path: &Path) -> Result<PublicKey, GitwayError> {
    let raw = fs::read_to_string(path).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => GitwayError::no_key_found(),
        _ => GitwayError::from(e),
    })?;
    if let Ok(pk) = PublicKey::from_openssh(&raw) {
        return Ok(pk);
    }
    let priv_path = resolve_signing_key_path(path)?;
    let priv_raw = fs::read_to_string(&priv_path)?;
    let privkey = PrivateKey::from_openssh(&priv_raw)
        .map_err(|e| GitwayError::invalid_config(format!("cannot parse signing key: {e}")))?;
    Ok(privkey.public_key().clone())
}

/// Writes the armored SSHSIG to the message-file companion (`.sig`)
/// when present, else to stdout.
fn write_sig_output(armored: &[u8], sig_out: Option<&Path>) -> Result<u32, GitwayError> {
    if let Some(path) = sig_out {
        fs::write(path, armored)?;
    } else {
        let mut out = io::stdout().lock();
        out.write_all(armored)?;
        out.flush()?;
    }
    Ok(0)
}

fn run_verify(p: &Parsed) -> Result<u32, GitwayError> {
    let Some(ns) = p.namespace.clone() else {
        return Err(GitwayError::invalid_config("-n NAMESPACE is required"));
    };
    let Some(signer) = p.signer_identity.clone() else {
        return Err(GitwayError::invalid_config("-I IDENTITY is required"));
    };
    let Some(sig_path) = p.signature_file.clone() else {
        return Err(GitwayError::invalid_config("-s SIG is required"));
    };
    let allowed_path = p
        .allowed_signers
        .clone()
        .or_else(|| p.file.clone())
        .ok_or_else(|| GitwayError::invalid_config("-f or --allowed-signers is required"))?;

    let armored = fs::read_to_string(&sig_path)?;
    let allowed = AllowedSigners::load(&allowed_path)?;
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data)?;
    let verified = sshsig::verify(&mut data.as_slice(), &armored, &signer, &ns, &allowed)?;

    // ssh-keygen prints "Good \"<ns>\" signature for <signer> with <algo> key <fingerprint>".
    println!(
        "Good \"{ns}\" signature for {signer} with ssh key {}",
        verified.fingerprint
    );
    Ok(0)
}

fn run_check_novalidate(p: &Parsed) -> Result<u32, GitwayError> {
    let Some(ns) = p.namespace.clone() else {
        return Err(GitwayError::invalid_config("-n NAMESPACE is required"));
    };
    let Some(sig_path) = p.signature_file.clone() else {
        return Err(GitwayError::invalid_config("-s SIG is required"));
    };
    let armored = fs::read_to_string(&sig_path)?;
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data)?;
    sshsig::check_novalidate(&mut data.as_slice(), &armored, &ns)?;
    println!("Good \"{ns}\" signature (cryptographic check only)");
    Ok(0)
}

fn run_find_principals(p: &Parsed) -> Result<u32, GitwayError> {
    let Some(ns) = p.namespace.clone() else {
        return Err(GitwayError::invalid_config("-n NAMESPACE is required"));
    };
    let Some(sig_path) = p.signature_file.clone() else {
        return Err(GitwayError::invalid_config("-s SIG is required"));
    };
    let allowed_path = p
        .allowed_signers
        .clone()
        .or_else(|| p.file.clone())
        .ok_or_else(|| GitwayError::invalid_config("-f or --allowed-signers is required"))?;
    let armored = fs::read_to_string(&sig_path)?;
    let allowed = AllowedSigners::load(&allowed_path)?;
    let principals = sshsig::find_principals(&armored, &allowed, &ns)?;
    for p in principals {
        println!("{p}");
    }
    Ok(0)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_kind(s: &str, bits: Option<u32>) -> Result<KeyType, GitwayError> {
    match s.to_ascii_lowercase().as_str() {
        "ed25519" => Ok(KeyType::Ed25519),
        "rsa" => Ok(KeyType::Rsa),
        "ecdsa" => match bits.unwrap_or(256) {
            256 => Ok(KeyType::EcdsaP256),
            384 => Ok(KeyType::EcdsaP384),
            521 => Ok(KeyType::EcdsaP521),
            other => Err(GitwayError::invalid_config(format!(
                "ECDSA requires -b 256|384|521, got {other}"
            ))),
        },
        other => Err(GitwayError::invalid_config(format!(
            "unsupported key type: {other}"
        ))),
    }
}

fn load_public_key(path: &Path) -> Result<PublicKey, GitwayError> {
    let raw = fs::read_to_string(path)?;
    if let Ok(pk) = PublicKey::from_openssh(raw.trim()) {
        return Ok(pk);
    }
    match PrivateKey::from_openssh(&raw) {
        Ok(sk) => Ok(sk.public_key().clone()),
        Err(e) => Err(GitwayError::invalid_config(format!(
            "cannot parse key: {e}"
        ))),
    }
}

/// Resolves `path` to a private-key file path.
///
/// If `path` already points at a private key, it is returned unchanged.
/// If `path` points at a `.pub` file (or any file that parses as a public
/// key in OpenSSH format), the same path without the `.pub` suffix is
/// returned — mirroring `ssh-keygen`'s behaviour when given a public key
/// but no agent is available.
///
/// # Errors
///
/// Returns [`GitwayError::no_key_found`] if neither `path` nor its
/// stripped-`.pub` counterpart exists, and [`GitwayError::invalid_config`]
/// if the file is neither a private key nor a public key.
fn resolve_signing_key_path(path: &Path) -> Result<PathBuf, GitwayError> {
    let raw = match fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(GitwayError::no_key_found());
        }
        Err(e) => return Err(GitwayError::from(e)),
    };

    // Private key? Use it directly.
    if PrivateKey::from_openssh(&raw).is_ok() {
        return Ok(path.to_owned());
    }

    // Public key? Look for the private key next to it by stripping
    // `.pub` (ssh-keygen's convention).
    if PublicKey::from_openssh(raw.trim()).is_ok() {
        let as_str = path.as_os_str().to_string_lossy().into_owned();
        if let Some(stripped) = as_str.strip_suffix(".pub") {
            let candidate = PathBuf::from(stripped);
            if candidate.exists() {
                return Ok(candidate);
            }
            return Err(GitwayError::invalid_config(format!(
                "public-key path {} given for signing, but no private key \
                 found at {}; load the key into an agent (phase 2) or \
                 pass the private-key path directly",
                path.display(),
                candidate.display(),
            )));
        }
        return Err(GitwayError::invalid_config(format!(
            "public-key path {} given for signing, but does not end in \
             `.pub`; cannot locate the matching private key",
            path.display(),
        )));
    }

    Err(GitwayError::invalid_config(format!(
        "file {} is neither a private nor public OpenSSH key",
        path.display(),
    )))
}

fn load_and_decrypt(path: &Path, old_pp: Option<&str>) -> Result<PrivateKey, GitwayError> {
    let pem = fs::read_to_string(path)?;
    let key = PrivateKey::from_openssh(&pem)
        .map_err(|e| GitwayError::invalid_config(format!("cannot parse key: {e}")))?;
    if !key.is_encrypted() {
        return Ok(key);
    }
    let pp: Zeroizing<String> = match old_pp {
        Some(s) => Zeroizing::new(s.to_owned()),
        None => rpassword::prompt_password(format!("Enter passphrase for {}: ", path.display()))
            .map(Zeroizing::new)
            .map_err(GitwayError::from)?,
    };
    key.decrypt(pp.as_bytes())
        .map_err(|e| GitwayError::signing(format!("decrypt failed: {e}")))
}

fn default_comment() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".to_owned());
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "localhost".to_owned());
    format!("{user}@{host}")
}

/// Returns the approximate bit-size of a public key for the `ssh-keygen -l`
/// display line.
///
/// ssh-keygen prints `"<bits> <fp> <comment> (<ALGO>)"` where `<bits>` is:
/// - 256 for Ed25519 and ECDSA P-256;
/// - 384 / 521 for the larger ECDSA curves;
/// - the RSA modulus bit length.
fn public_bit_estimate(pk: &PublicKey) -> u32 {
    // ssh-key 0.6 exposes `key_data()` which includes algorithm-specific
    // parameters; for our display purpose we map algorithms directly.
    match pk.algorithm() {
        ssh_key::Algorithm::Ed25519 => 256,
        ssh_key::Algorithm::Ecdsa { curve } => match curve {
            ssh_key::EcdsaCurve::NistP256 => 256,
            ssh_key::EcdsaCurve::NistP384 => 384,
            ssh_key::EcdsaCurve::NistP521 => 521,
        },
        // RSA bit length is modulus length; ssh-key exposes it via the inner
        // key data. If the type is unavailable we fall back to 0 rather than
        // panicking — the user still sees the fingerprint.
        ssh_key::Algorithm::Rsa { .. } => rsa_modulus_bits(pk).unwrap_or(0),
        _ => 0,
    }
}

fn rsa_modulus_bits(pk: &PublicKey) -> Option<u32> {
    if let ssh_key::public::KeyData::Rsa(rsa) = pk.key_data() {
        // `n` is a Mpint; the public modulus length in bits ≈ bytes * 8.
        let bytes = rsa.n.as_bytes().len();
        u32::try_from(bytes.saturating_mul(8)).ok()
    } else {
        None
    }
}
