// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-21
//! Thin dispatcher for `gitway sign` and `gitway keygen sign`.
//!
//! Both paths share this implementation; `gitway sign` is the ergonomic
//! top-level alias, `gitway keygen sign` is the positional form that mirrors
//! `ssh-keygen -Y sign`.

use std::fs;
use std::path::Path;

use ssh_key::{HashAlg, PrivateKey};
use zeroize::Zeroizing;

use anvil_ssh::auth::{find_identity, IdentityResolution};
use anvil_ssh::keygen;
use anvil_ssh::sshsig;
use anvil_ssh::GitwayError;

use crate::cli::{HashKind, SignArgs};
use crate::keygen::{hashkind_to_sshkey, open_input, write_output};
use crate::{now_iso8601, prompt_passphrase, OutputMode};

/// Runs `gitway sign` / `gitway keygen sign`.
pub fn run(args: &SignArgs, mode: OutputMode) -> Result<u32, GitwayError> {
    let key_path = resolve_key_path(args.key.as_deref())?;
    let key = load_and_decrypt(&key_path)?;

    let mut reader = open_input(args.input.as_deref())?;
    let hash = hashkind_to_sshkey(args.hash);
    let armored = sshsig::sign(&mut reader, &key, &args.namespace, hash)?;

    // Written to stdout in both JSON and human modes when no --output is
    // given — ssh-keygen's -Y sign writes only the signature to stdout and
    // git relies on that. We preserve the behavior for the default path;
    // JSON mode emits instead to stderr so that agentic callers can still
    // choose stdout-as-signature by omitting --json.
    match (mode, args.output.as_deref()) {
        (OutputMode::Json, explicit) => {
            // Write the signature to the requested target (or stdout).
            write_output(explicit, armored.as_bytes())?;
            // Emit the structured record to stderr so it cannot contaminate
            // a tool reading stdout for the signature bytes.
            let record = serde_json::json!({
                "metadata": {
                    "tool": "gitway",
                    "version": env!("CARGO_PKG_VERSION"),
                    "command": "gitway sign",
                    "timestamp": now_iso8601(),
                },
                "data": {
                    "signer_fingerprint": keygen::fingerprint(key.public_key(), HashAlg::Sha256),
                    "namespace": args.namespace,
                    "hash": match args.hash {
                        HashKind::Sha256 => "sha256",
                        HashKind::Sha512 => "sha512",
                    },
                    "sig_armored": armored,
                    "output": explicit.map_or_else(|| "-".to_owned(), |p| p.display().to_string()),
                }
            });
            // Use eprintln! rather than emit_json (which writes stdout) so
            // we do not overwrite the armored signature on stdout.
            eprintln!("{record}");
        }
        (OutputMode::Human, explicit) => {
            write_output(explicit, armored.as_bytes())?;
        }
    }
    Ok(0)
}

fn resolve_key_path(explicit: Option<&Path>) -> Result<std::path::PathBuf, GitwayError> {
    if let Some(p) = explicit {
        return Ok(p.to_owned());
    }
    // Auto-discovery: use the same search order as the transport path so
    // users who already have ~/.ssh/id_ed25519 picked up for fetch/push get
    // the same key for signing.
    let config = anvil_ssh::GitwayConfig::github();
    match find_identity(&config)? {
        IdentityResolution::Found { path, .. } | IdentityResolution::Encrypted { path } => Ok(path),
        IdentityResolution::NotFound => Err(GitwayError::no_key_found()),
    }
}

fn load_and_decrypt(path: &Path) -> Result<PrivateKey, GitwayError> {
    let pem = fs::read_to_string(path)?;
    let key = PrivateKey::from_openssh(&pem).map_err(|e| {
        GitwayError::invalid_config(format!("cannot parse {}: {e}", path.display()))
    })?;
    if !key.is_encrypted() {
        return Ok(key);
    }
    // Encrypted: collect passphrase and decrypt.
    let pp: Zeroizing<String> = prompt_passphrase(path)?;
    key.decrypt(pp.as_bytes())
        .map_err(|e| GitwayError::signing(format!("failed to decrypt private key: {e}")))
}
