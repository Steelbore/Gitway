// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-21
//! Parser for the OpenSSH `allowed_signers` file format.
//!
//! Git uses this file to map SSH public keys to the principals (usually email
//! addresses) that are authorized to sign commits under a given namespace.
//! The format is documented in `ssh-keygen(1)` under the `ALLOWED SIGNERS`
//! heading.
//!
//! Each non-blank, non-comment line has the form:
//!
//! ```text
//! principals [options] key-type base64-key [comment]
//! ```
//!
//! - `principals` is a comma-separated list of fnmatch-style patterns (a
//!   quoted string if any pattern contains spaces).
//! - `options` is an optional comma-separated list of `key[="value"]` pairs.
//!   Only `namespaces="<list>"` is honored for git's purposes.
//! - `key-type` + `base64-key` is the public key, in the same wire form used
//!   by `authorized_keys`.
//!
//! # Examples
//!
//! ```no_run
//! use gitway_lib::allowed_signers::AllowedSigners;
//!
//! let signers = AllowedSigners::load(std::path::Path::new("~/.config/git/allowed_signers"))
//!     .unwrap();
//! for entry in signers.entries() {
//!     println!("{:?}", entry.principals);
//! }
//! ```
//!
//! # Errors
//!
//! [`AllowedSigners::parse`] rejects lines that are syntactically ill-formed
//! (missing key type, unterminated quoted principals, invalid base64). Blank
//! lines and `#`-comments are skipped silently.

use std::fs;
use std::path::Path;

use ssh_key::PublicKey;

use crate::GitwayError;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A single principal-to-key mapping parsed from an `allowed_signers` file.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Fnmatch-style patterns separated by commas in the source file.
    ///
    /// Each pattern may be prefixed with `!` for negation, as in OpenSSH's
    /// `Match` block syntax.
    pub principals: Vec<String>,
    /// Comma-separated list of namespaces the key is authorized to sign under,
    /// parsed from a `namespaces="..."` option.
    ///
    /// `None` means "any namespace is accepted" (the default per OpenSSH).
    pub namespaces: Option<Vec<String>>,
    /// Whether the entry is marked as a certificate authority (`cert-authority`).
    pub cert_authority: bool,
    /// The public key in OpenSSH wire form.
    pub public_key: PublicKey,
}

/// The parsed contents of an `allowed_signers` file.
#[derive(Debug, Clone)]
pub struct AllowedSigners {
    entries: Vec<Entry>,
}

impl AllowedSigners {
    /// Parses an `allowed_signers` document from a string.
    ///
    /// # Errors
    ///
    /// Returns [`GitwayError`] on the first malformed line.
    pub fn parse(input: &str) -> Result<Self, GitwayError> {
        let mut entries = Vec::new();
        for (lineno, raw) in input.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let entry = parse_line(line)
                .map_err(|msg| {
                    GitwayError::invalid_config(format!(
                        "allowed_signers line {}: {msg}",
                        lineno + 1
                    ))
                })?;
            entries.push(entry);
        }
        Ok(Self { entries })
    }

    /// Loads and parses an `allowed_signers` file from disk.
    ///
    /// # Errors
    ///
    /// Returns [`GitwayError`] if the file cannot be read or contains
    /// malformed lines.
    pub fn load(path: &Path) -> Result<Self, GitwayError> {
        let contents = fs::read_to_string(path)?;
        Self::parse(&contents)
    }

    /// Returns the number of parsed entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the file contained no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns all entries.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Returns the principals authorized to sign under `namespace` with `public_key`.
    ///
    /// An entry matches when its public key equals `public_key` exactly and
    /// either has no `namespaces` restriction or includes `namespace` in its
    /// list.
    #[must_use]
    pub fn find_principals<'a>(
        &'a self,
        public_key: &PublicKey,
        namespace: &str,
    ) -> Vec<&'a str> {
        let mut out = Vec::new();
        for entry in &self.entries {
            if entry.public_key != *public_key {
                continue;
            }
            if let Some(ref allowed) = entry.namespaces {
                if !allowed.iter().any(|ns| ns == namespace) {
                    continue;
                }
            }
            for p in &entry.principals {
                out.push(p.as_str());
            }
        }
        out
    }

    /// Returns `true` if any entry authorizes `identity` to sign under
    /// `namespace` with `public_key`.
    ///
    /// `identity` is matched against each entry's principal patterns using
    /// fnmatch-style globs (`*`, `?`, character classes). Negation prefixes
    /// (`!pattern`) are honored — a matching negation rejects the entry.
    #[must_use]
    pub fn is_authorized(
        &self,
        identity: &str,
        public_key: &PublicKey,
        namespace: &str,
    ) -> bool {
        for entry in &self.entries {
            if entry.public_key != *public_key {
                continue;
            }
            if let Some(ref allowed) = entry.namespaces {
                if !allowed.iter().any(|ns| ns == namespace) {
                    continue;
                }
            }
            if principals_match(&entry.principals, identity) {
                return true;
            }
        }
        false
    }
}

// ── Parser helpers ────────────────────────────────────────────────────────────

/// Parses a single non-blank, non-comment line.
fn parse_line(line: &str) -> Result<Entry, String> {
    let mut rest = line;

    // 1. Principals (possibly quoted).
    let (principals_raw, after) = take_field(rest)?;
    rest = after.trim_start();
    let principals = split_principals(&principals_raw);
    if principals.is_empty() {
        return Err("empty principals list".to_owned());
    }

    // 2. Optional options section, then key-type, then base64 key.
    //
    // Options are recognised by not being a known SSH key algorithm name.
    // OpenSSH's ssh-keygen uses the same heuristic.
    let (maybe_options, after) = take_field(rest)?;
    let (options_str, key_type, key_base64) = if is_ssh_key_algorithm(&maybe_options) {
        let (kt, after2) = (maybe_options, after);
        let (kb, _after3) = take_field(after2.trim_start())?;
        (String::new(), kt, kb)
    } else {
        rest = after.trim_start();
        let (kt, after2) = take_field(rest)?;
        if !is_ssh_key_algorithm(&kt) {
            return Err(format!("expected key algorithm, got {kt:?}"));
        }
        let (kb, _after3) = take_field(after2.trim_start())?;
        (maybe_options, kt, kb)
    };

    let (namespaces, cert_authority) = parse_options(&options_str);

    // 3. Reassemble the OpenSSH public-key line and parse it.
    let openssh = format!("{key_type} {key_base64}");
    let public_key = PublicKey::from_openssh(&openssh)
        .map_err(|e| format!("invalid public key: {e}"))?;

    Ok(Entry {
        principals,
        namespaces,
        cert_authority,
        public_key,
    })
}

/// Consumes the next whitespace-delimited field, honoring `"quoted strings"`.
fn take_field(input: &str) -> Result<(String, &str), String> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err("unexpected end of line".to_owned());
    }
    if let Some(stripped) = input.strip_prefix('"') {
        let end = stripped
            .find('"')
            .ok_or_else(|| "unterminated quoted string".to_owned())?;
        let field = stripped[..end].to_owned();
        let remainder = &stripped[end + 1..];
        Ok((field, remainder))
    } else {
        let end = input
            .find(char::is_whitespace)
            .unwrap_or(input.len());
        Ok((input[..end].to_owned(), &input[end..]))
    }
}

/// Splits a comma-separated principals field into individual patterns.
fn split_principals(field: &str) -> Vec<String> {
    field
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(std::borrow::ToOwned::to_owned)
        .collect()
}

/// Parses the options field into `(namespaces, cert_authority)`.
///
/// Unknown options (including `valid-after`, `valid-before`,
/// `verify-required`) are silently accepted and ignored — callers that need
/// time-bound verification must check them at a higher layer.
fn parse_options(options: &str) -> (Option<Vec<String>>, bool) {
    if options.is_empty() {
        return (None, false);
    }
    let mut namespaces = None;
    let mut cert_authority = false;
    for opt in split_options(options) {
        if opt.eq_ignore_ascii_case("cert-authority") {
            cert_authority = true;
        } else if let Some(value) = opt.strip_prefix("namespaces=") {
            let trimmed = value.trim_matches('"');
            namespaces = Some(
                trimmed
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(std::borrow::ToOwned::to_owned)
                    .collect(),
            );
        }
    }
    (namespaces, cert_authority)
}

/// Splits an options string on commas, respecting `"quoted"` values.
fn split_options(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    for c in input.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                current.push(c);
            }
            ',' if !in_quote => {
                let s = current.trim().to_owned();
                if !s.is_empty() {
                    out.push(s);
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }
    let s = current.trim().to_owned();
    if !s.is_empty() {
        out.push(s);
    }
    out
}

/// Returns `true` when `s` names an SSH public-key algorithm understood by
/// `ssh-key` 0.6.
fn is_ssh_key_algorithm(s: &str) -> bool {
    matches!(
        s,
        "ssh-ed25519"
            | "ssh-rsa"
            | "rsa-sha2-256"
            | "rsa-sha2-512"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "ssh-dss"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    )
}

/// Tests whether `identity` matches any positive pattern without being
/// rejected by a negation (`!pattern`).
fn principals_match(patterns: &[String], identity: &str) -> bool {
    let mut matched = false;
    for p in patterns {
        let (negated, pat) = p
            .strip_prefix('!')
            .map_or((false, p.as_str()), |rest| (true, rest));
        if glob_match(pat, identity) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

/// Fnmatch-style matcher supporting `*` and `?`. Case-sensitive.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_inner(&p, 0, &t, 0)
}

fn glob_match_inner(p: &[char], mut pi: usize, t: &[char], mut ti: usize) -> bool {
    while pi < p.len() {
        match p[pi] {
            '*' => {
                if pi + 1 == p.len() {
                    return true;
                }
                for skip in ti..=t.len() {
                    if glob_match_inner(p, pi + 1, t, skip) {
                        return true;
                    }
                }
                return false;
            }
            '?' => {
                if ti >= t.len() {
                    return false;
                }
                pi += 1;
                ti += 1;
            }
            c => {
                if ti >= t.len() || t[ti] != c {
                    return false;
                }
                pi += 1;
                ti += 1;
            }
        }
    }
    ti == t.len()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEr3gQn+Fg1J1K5HT+0n2N1iA3Gn+Yx3hQJ3z4PxZQ7J tim@example.com";

    #[test]
    fn parse_single_entry() {
        let input = format!("tim@example.com {SAMPLE_ED25519}");
        let signers = AllowedSigners::parse(&input).unwrap();
        assert_eq!(signers.len(), 1);
        assert_eq!(signers.entries()[0].principals, vec!["tim@example.com"]);
        assert!(signers.entries()[0].namespaces.is_none());
    }

    #[test]
    fn parse_skips_blanks_and_comments() {
        let input = format!(
            "\n# top comment\n\n   # indented comment\ntim@example.com {SAMPLE_ED25519}\n"
        );
        let signers = AllowedSigners::parse(&input).unwrap();
        assert_eq!(signers.len(), 1);
    }

    #[test]
    fn parse_namespaces_option() {
        let input = format!(
            "tim@example.com namespaces=\"git,file\" {SAMPLE_ED25519}"
        );
        let signers = AllowedSigners::parse(&input).unwrap();
        let ns = signers.entries()[0].namespaces.as_ref().unwrap();
        assert_eq!(ns, &vec!["git".to_owned(), "file".to_owned()]);
    }

    #[test]
    fn parse_multiple_principals_and_quoted() {
        let input = format!(
            "\"alice@example.com,bob@example.com\" {SAMPLE_ED25519}"
        );
        let signers = AllowedSigners::parse(&input).unwrap();
        assert_eq!(
            signers.entries()[0].principals,
            vec!["alice@example.com", "bob@example.com"]
        );
    }

    #[test]
    fn parse_cert_authority() {
        let input = format!("*@example.com cert-authority {SAMPLE_ED25519}");
        let signers = AllowedSigners::parse(&input).unwrap();
        assert!(signers.entries()[0].cert_authority);
    }

    #[test]
    fn glob_matches_wildcard() {
        assert!(glob_match("*@example.com", "tim@example.com"));
        assert!(!glob_match("*@example.com", "tim@other.org"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
    }

    #[test]
    fn is_authorized_respects_negation() {
        let input = format!(
            "*@example.com,!evil@example.com {SAMPLE_ED25519}"
        );
        let signers = AllowedSigners::parse(&input).unwrap();
        let key = &signers.entries()[0].public_key;
        assert!(signers.is_authorized("tim@example.com", key, "git"));
        assert!(!signers.is_authorized("evil@example.com", key, "git"));
    }

    #[test]
    fn is_authorized_respects_namespace_restriction() {
        let input = format!(
            "tim@example.com namespaces=\"git\" {SAMPLE_ED25519}"
        );
        let signers = AllowedSigners::parse(&input).unwrap();
        let key = &signers.entries()[0].public_key;
        assert!(signers.is_authorized("tim@example.com", key, "git"));
        assert!(!signers.is_authorized("tim@example.com", key, "file"));
    }

    #[test]
    fn rejects_missing_key() {
        let err = AllowedSigners::parse("tim@example.com\n").unwrap_err();
        assert!(err.to_string().contains("line 1"));
    }
}
