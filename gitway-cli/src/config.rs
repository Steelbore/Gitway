// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Dispatcher for the `gitway config` subcommand tree (M12.7).
//!
//! Maps parsed [`cli::ConfigSubcommand`] variants onto
//! [`anvil_ssh::ssh_config::resolve`] and renders the [`ResolvedSshConfig`]
//! result either in `ssh -G` mirror form (human / default) or as a JSON
//! object (`--json`).
//!
//! Path-shaped values that look like private-key files are redacted to
//! `[REDACTED]` per NFR-20 unless `--show-secrets` is passed.

use std::path::Path;

use anvil_ssh::ssh_config::{resolve, AlgList, ResolvedSshConfig, SshConfigPaths};
use anvil_ssh::{AnvilError, StrictHostKeyChecking};

use crate::cli::{ConfigShowArgs, ConfigSubcommand};
use crate::{emit_json, now_iso8601, OutputMode};

/// Dispatches one `gitway config <sub>` invocation.
pub fn run(sub: ConfigSubcommand, mode: OutputMode) -> Result<u32, AnvilError> {
    match sub {
        ConfigSubcommand::Show(args) => run_show(&args, mode),
    }
}

fn run_show(args: &ConfigShowArgs, mode: OutputMode) -> Result<u32, AnvilError> {
    let paths = ssh_config_paths_from_args(args);
    let resolved = resolve(&args.host, &paths)?;

    match mode {
        OutputMode::Json => emit_json_show(args, &resolved),
        OutputMode::Human => emit_human_show(args, &resolved),
    }

    Ok(0)
}

/// Builds the [`SshConfigPaths`] from the CLI flags, applying the `--user-config`
/// / `--system-config` overrides on top of the platform defaults.  An empty
/// override (e.g. `--system-config=`) disables that tier.
fn ssh_config_paths_from_args(args: &ConfigShowArgs) -> SshConfigPaths {
    let mut paths = SshConfigPaths::default_paths();
    if let Some(user) = &args.user_config {
        paths.user = if user.as_os_str().is_empty() {
            None
        } else {
            Some(user.clone())
        };
    }
    if let Some(system) = &args.system_config {
        paths.system = if system.as_os_str().is_empty() {
            None
        } else {
            Some(system.clone())
        };
    }
    paths
}

// ── Human output (mirrors `ssh -G`) ──────────────────────────────────────────

fn emit_human_show(args: &ConfigShowArgs, resolved: &ResolvedSshConfig) {
    let show_secrets = args.show_secrets;
    if let Some(v) = &resolved.hostname {
        println!("hostname {v}");
    }
    if let Some(v) = &resolved.user {
        println!("user {v}");
    }
    if let Some(v) = resolved.port {
        println!("port {v}");
    }
    for path in &resolved.identity_files {
        println!("identityfile {}", display_path(path, show_secrets));
    }
    if let Some(v) = resolved.identities_only {
        println!("identitiesonly {}", yes_no(v));
    }
    if let Some(p) = &resolved.identity_agent {
        println!("identityagent {}", display_path(p, show_secrets));
    }
    for path in &resolved.certificate_files {
        println!(
            "certificatefile {}",
            display_path(path, /*never redacted*/ true)
        );
    }
    if let Some(v) = &resolved.proxy_command {
        println!("proxycommand {v}");
    }
    if let Some(v) = &resolved.proxy_jump {
        println!("proxyjump {v}");
        // FR-58: when a ProxyJump chain is set, parse and emit one
        // line per hop so the user sees the resolved chain (matches
        // the spirit of `ssh -G`'s output for chained configs).  We
        // tolerate parse failure here — the raw `proxyjump` line
        // above already records what was set; per-hop visualization
        // is purely advisory.
        if !v.eq_ignore_ascii_case("none") {
            match anvil_ssh::proxy::parse_jump_chain(v) {
                Ok(chain) => {
                    for (idx, hop) in chain.iter().enumerate() {
                        let user_prefix = hop
                            .user
                            .as_deref()
                            .map(|u| format!("{u}@"))
                            .unwrap_or_default();
                        println!(
                            "proxyjump_hop_{}_to {}{}:{}",
                            idx + 1,
                            user_prefix,
                            hop.host,
                            hop.port,
                        );
                    }
                }
                Err(e) => {
                    eprintln!("gitway config show: warning: ProxyJump unparsable: {e}");
                }
            }
        }
    }
    for path in &resolved.user_known_hosts_files {
        println!(
            "userknownhostsfile {}",
            display_path(path, /*never redacted*/ true)
        );
    }
    if let Some(policy) = resolved.strict_host_key_checking {
        println!("stricthostkeychecking {}", strict_label(policy));
    }
    if let Some(AlgList(s)) = &resolved.host_key_algorithms {
        println!("hostkeyalgorithms {s}");
    }
    if let Some(AlgList(s)) = &resolved.kex_algorithms {
        println!("kexalgorithms {s}");
    }
    if let Some(AlgList(s)) = &resolved.ciphers {
        println!("ciphers {s}");
    }
    if let Some(AlgList(s)) = &resolved.macs {
        println!("macs {s}");
    }
    if let Some(d) = resolved.connect_timeout {
        println!("connecttimeout {}", d.as_secs());
    }
    if let Some(v) = resolved.connection_attempts {
        println!("connectionattempts {v}");
    }
}

// ── JSON output ──────────────────────────────────────────────────────────────

fn emit_json_show(args: &ConfigShowArgs, resolved: &ResolvedSshConfig) {
    let mut redacted: Vec<&'static str> = Vec::new();
    let identity_files: Vec<String> = resolved
        .identity_files
        .iter()
        .map(|p| {
            let s = display_path(p, args.show_secrets);
            if s == REDACTED {
                redacted.push("identityfile");
            }
            s
        })
        .collect();
    let identity_agent = resolved.identity_agent.as_ref().map(|p| {
        let s = display_path(p, args.show_secrets);
        if s == REDACTED {
            redacted.push("identityagent");
        }
        s
    });

    let provenance: Vec<serde_json::Value> = resolved
        .provenance
        .iter()
        .map(|src| {
            serde_json::json!({
                "directive": src.directive,
                "file": src.file.to_string_lossy(),
                "line": src.line,
            })
        })
        .collect();

    let data = serde_json::json!({
        "host": args.host,
        "hostname": resolved.hostname,
        "user": resolved.user,
        "port": resolved.port,
        "identity_files": identity_files,
        "identities_only": resolved.identities_only,
        "identity_agent": identity_agent,
        "certificate_files": resolved
            .certificate_files
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        "proxy_command": resolved.proxy_command,
        "proxy_jump": resolved.proxy_jump,
        "proxy_jump_chain": jump_chain_json(resolved.proxy_jump.as_deref()),
        "user_known_hosts_files": resolved
            .user_known_hosts_files
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        "strict_host_key_checking": resolved
            .strict_host_key_checking
            .map(strict_label),
        "host_key_algorithms": resolved.host_key_algorithms.as_ref().map(|a| a.0.clone()),
        "kex_algorithms": resolved.kex_algorithms.as_ref().map(|a| a.0.clone()),
        "ciphers": resolved.ciphers.as_ref().map(|a| a.0.clone()),
        "macs": resolved.macs.as_ref().map(|a| a.0.clone()),
        "connect_timeout_secs": resolved.connect_timeout.map(|d| d.as_secs()),
        "connection_attempts": resolved.connection_attempts,
        "provenance": provenance,
        "redacted": redacted,
    });

    emit_json(&serde_json::json!({
        "metadata": {
            "tool": "gitway",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "gitway config show",
            "timestamp": now_iso8601(),
        },
        "data": data,
    }));
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const REDACTED: &str = "[REDACTED]";

/// Returns the path's string representation, or `[REDACTED]` if it
/// looks like a private-key file under a typical key directory and
/// `show_secrets` is `false`.
fn display_path(path: &Path, show_secrets: bool) -> String {
    if show_secrets || !looks_like_private_key(path) {
        return path.to_string_lossy().into_owned();
    }
    REDACTED.to_owned()
}

/// Heuristic redaction filter (NFR-20):
/// - The filename contains `id_` (e.g. `id_ed25519`, `id_rsa`).
/// - It does NOT end in `.pub` (which is the public half).
/// - It is under `~/.ssh/` or `~/.config/gitway/keys/` (best-effort).
fn looks_like_private_key(path: &Path) -> bool {
    let Some(name_os) = path.file_name() else {
        return false;
    };
    let Some(name) = name_os.to_str() else {
        return false;
    };
    if Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pub"))
    {
        return false;
    }
    if !name.contains("id_") {
        return false;
    }
    let path_str = path.to_string_lossy();
    path_str.contains(".ssh") || path_str.contains("/.config/gitway/keys")
}

fn strict_label(policy: StrictHostKeyChecking) -> &'static str {
    match policy {
        StrictHostKeyChecking::Yes => "yes",
        StrictHostKeyChecking::No => "no",
        StrictHostKeyChecking::AcceptNew => "accept-new",
    }
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// Parses `raw` as a `ProxyJump` chain and returns it as a JSON array
/// of `{host, port, user}` objects (FR-58).  Returns
/// [`serde_json::Value::Null`] when the input is `None`, the FR-59
/// disable sentinel `"none"`, or unparsable — the raw string is still
/// available via the sibling `proxy_jump` key.
fn jump_chain_json(raw: Option<&str>) -> serde_json::Value {
    let Some(raw) = raw else {
        return serde_json::Value::Null;
    };
    if raw.eq_ignore_ascii_case("none") {
        return serde_json::Value::Null;
    }
    match anvil_ssh::proxy::parse_jump_chain(raw) {
        Ok(chain) => serde_json::Value::Array(
            chain
                .into_iter()
                .map(|hop| {
                    serde_json::json!({
                        "host": hop.host,
                        "port": hop.port,
                        "user": hop.user,
                    })
                })
                .collect(),
        ),
        Err(_) => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn looks_like_private_key_positive() {
        assert!(looks_like_private_key(&PathBuf::from(
            "/home/u/.ssh/id_ed25519"
        )));
        assert!(looks_like_private_key(&PathBuf::from(
            "C:\\Users\\u\\.ssh\\id_rsa"
        )));
        assert!(looks_like_private_key(&PathBuf::from(
            "/home/u/.config/gitway/keys/id_ecdsa",
        )));
    }

    #[test]
    fn looks_like_private_key_negative() {
        // Public key: not redacted.
        assert!(!looks_like_private_key(&PathBuf::from(
            "/home/u/.ssh/id_ed25519.pub",
        )));
        // No `id_` in the filename: not redacted.
        assert!(!looks_like_private_key(&PathBuf::from(
            "/home/u/.ssh/known_hosts",
        )));
        // Outside the typical key directories: not redacted (heuristic).
        assert!(!looks_like_private_key(&PathBuf::from("/etc/ssh/id_host")));
    }

    #[test]
    fn display_path_redacts_when_secret_default() {
        let path = PathBuf::from("/home/u/.ssh/id_ed25519");
        assert_eq!(display_path(&path, false), "[REDACTED]");
        assert_eq!(display_path(&path, true), "/home/u/.ssh/id_ed25519");
    }

    #[test]
    fn display_path_passes_through_non_secrets() {
        let path = PathBuf::from("/etc/ssh/ssh_known_hosts");
        assert_eq!(display_path(&path, false), "/etc/ssh/ssh_known_hosts");
    }

    #[test]
    fn ssh_config_paths_empty_override_disables_tier() {
        let args = ConfigShowArgs {
            host: "h".to_owned(),
            user_config: Some(PathBuf::new()),
            system_config: Some(PathBuf::new()),
            show_secrets: false,
        };
        let paths = ssh_config_paths_from_args(&args);
        assert!(paths.user.is_none());
        assert!(paths.system.is_none());
    }

    #[test]
    fn ssh_config_paths_explicit_override() {
        let args = ConfigShowArgs {
            host: "h".to_owned(),
            user_config: Some(PathBuf::from("/custom/user")),
            system_config: Some(PathBuf::from("/custom/system")),
            show_secrets: false,
        };
        let paths = ssh_config_paths_from_args(&args);
        assert_eq!(paths.user, Some(PathBuf::from("/custom/user")));
        assert_eq!(paths.system, Some(PathBuf::from("/custom/system")));
    }
}
