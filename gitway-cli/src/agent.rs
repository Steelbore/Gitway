// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Dispatcher for the `gitway agent` subcommand tree.
//!
//! Cross-platform as of v0.6.1. The transport picks itself: on Unix
//! we connect to a Unix domain socket, on Windows to a named pipe
//! (conventionally `\\.\pipe\openssh-ssh-agent` — the OpenSSH for
//! Windows default — or a Gitway-specific pipe of the user's choice).
//!
//! A few operations remain Unix-only and fall back to a clear error
//! on Windows: `gitway agent stop` (no `SIGTERM` equivalent for a
//! console app) and background-mode `gitway agent start` without
//! `-D` (no `setsid(2)`). Windows users stick to `-D` and let a
//! launcher (`start /B`, a Scheduled Task, or a Windows service
//! wrapper) handle backgrounding.
//!
//! Maps parsed [`cli::AgentSubcommand`] variants onto
//! [`anvil_ssh::agent::client::Agent`] operations. All user-facing output
//! lives here; the library layer stays output-agnostic.

use std::fs;
use std::path::Path;
use std::time::Duration;

use ssh_key::{HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use anvil_ssh::agent::client::Agent;
use anvil_ssh::keygen::fingerprint;
use anvil_ssh::AnvilError;

use crate::cli::{
    AgentAddArgs, AgentListArgs, AgentLockArgs, AgentRemoveArgs, AgentStartArgs, AgentStopArgs,
    AgentSubcommand, HashKind,
};
use crate::{emit_json, emit_json_line, now_iso8601, prompt_passphrase, OutputMode};

use anvil_ssh::agent::daemon::{self, AgentDaemonConfig};

// Imports needed by `run_stop`, declared at module scope so clippy's
// items-after-statements lint stays happy. Unix-only — the Windows
// `run_stop` has its own implementation below that returns a clear
// "not supported" error.
#[cfg(unix)]
use nix::sys::signal::{kill, Signal};
#[cfg(unix)]
use nix::unistd::Pid;

// ── Entry point ───────────────────────────────────────────────────────────────

/// Dispatches one `gitway agent <sub>` invocation.
///
/// Async to let the `Start` arm drive the agent daemon's accept loop on
/// the outer `#[tokio::main]` runtime; the other arms are sync and run
/// to completion before returning.
pub async fn run(sub: AgentSubcommand, mode: OutputMode) -> Result<u32, AnvilError> {
    match sub {
        AgentSubcommand::Add(args) => run_add(&args, mode),
        AgentSubcommand::List(args) => run_list(&args, mode),
        AgentSubcommand::Remove(args) => run_remove(&args, mode),
        AgentSubcommand::Lock(args) => run_lock(&args, mode, /* lock = */ true),
        AgentSubcommand::Unlock(args) => run_lock(&args, mode, /* lock = */ false),
        AgentSubcommand::Start(args) => run_start(&args, mode).await,
        AgentSubcommand::Stop(args) => run_stop(&args, mode),
    }
}

// ── add ───────────────────────────────────────────────────────────────────────

fn run_add(args: &AgentAddArgs, mode: OutputMode) -> Result<u32, AnvilError> {
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
fn default_key_paths() -> Result<Vec<std::path::PathBuf>, AnvilError> {
    let home =
        dirs::home_dir().ok_or_else(|| AnvilError::invalid_config("cannot determine $HOME"))?;
    let candidates = ["id_ed25519", "id_ecdsa", "id_rsa"];
    let found: Vec<_> = candidates
        .iter()
        .map(|name| home.join(".ssh").join(name))
        .filter(|p| p.exists())
        .collect();
    if found.is_empty() {
        return Err(AnvilError::no_key_found());
    }
    Ok(found)
}

/// Loads and (if necessary) decrypts a private key, prompting for the
/// passphrase via the shared `prompt_passphrase` helper.
fn load_private_key(path: &Path) -> Result<PrivateKey, AnvilError> {
    let pem = fs::read_to_string(path)?;
    let key = PrivateKey::from_openssh(&pem)
        .map_err(|e| AnvilError::invalid_config(format!("cannot parse {}: {e}", path.display())))?;
    if !key.is_encrypted() {
        return Ok(key);
    }
    let pp: Zeroizing<String> = prompt_passphrase(path)?;
    key.decrypt(pp.as_bytes())
        .map_err(|e| AnvilError::signing(format!("failed to decrypt {}: {e}", path.display())))
}

// ── list ──────────────────────────────────────────────────────────────────────

fn run_list(args: &AgentListArgs, mode: OutputMode) -> Result<u32, AnvilError> {
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
                        AnvilError::signing(format!("failed to serialize public key: {e}"))
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

fn run_remove(args: &AgentRemoveArgs, mode: OutputMode) -> Result<u32, AnvilError> {
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
        return Err(AnvilError::invalid_config(
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
fn load_public_or_derive(path: &Path) -> Result<PublicKey, AnvilError> {
    let raw = fs::read_to_string(path)?;
    if let Ok(pk) = PublicKey::from_openssh(raw.trim()) {
        return Ok(pk);
    }
    match PrivateKey::from_openssh(&raw) {
        Ok(sk) => Ok(sk.public_key().clone()),
        Err(e) => Err(AnvilError::invalid_config(format!(
            "cannot parse {}: {e}",
            path.display()
        ))),
    }
}

// ── lock / unlock ─────────────────────────────────────────────────────────────

fn run_lock(args: &AgentLockArgs, mode: OutputMode, lock: bool) -> Result<u32, AnvilError> {
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
fn prompt_lock_passphrase(lock: bool) -> Result<Zeroizing<String>, AnvilError> {
    if lock {
        let first = rpassword::prompt_password("Agent lock passphrase: ")
            .map(Zeroizing::new)
            .map_err(AnvilError::from)?;
        let confirm = rpassword::prompt_password("Confirm lock passphrase: ")
            .map(Zeroizing::new)
            .map_err(AnvilError::from)?;
        if *first != *confirm {
            return Err(AnvilError::invalid_config(
                "passphrases did not match — aborting",
            ));
        }
        Ok(first)
    } else {
        rpassword::prompt_password("Agent unlock passphrase: ")
            .map(Zeroizing::new)
            .map_err(AnvilError::from)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hashkind_to_sshkey(k: HashKind) -> HashAlg {
    match k {
        HashKind::Sha256 => HashAlg::Sha256,
        HashKind::Sha512 => HashAlg::Sha512,
    }
}

// ── start / stop ──────────────────────────────────────────────────────────────

/// Marker the parent sets in the detached child's environment so the
/// child knows to call `setsid(2)` + close stdio before running the
/// accept loop. Internal — not a user-facing knob.
const DAEMONIZED_MARKER: &str = "GITWAY_AGENT_DAEMONIZED";

async fn run_start(args: &AgentStartArgs, _mode: OutputMode) -> Result<u32, AnvilError> {
    let is_daemonized_child = std::env::var_os(DAEMONIZED_MARKER).is_some();

    // Two entry points meet here:
    //   1. `-D`: user wants a plain foreground daemon (systemd unit,
    //      debugging, Ctrl-C friendly).
    //   2. the detached child we respawned from `run_background_start`:
    //      inherits the marker env var and finishes the detach itself.
    // Everything else (no `-D`, no marker) respawns on Unix.
    if args.foreground || is_daemonized_child {
        #[cfg(unix)]
        if is_daemonized_child {
            finalize_detach();
        }
        return run_daemon_loop(args).await;
    }

    #[cfg(unix)]
    {
        run_background_start(args)
    }
    #[cfg(not(unix))]
    {
        // Windows has no `setsid(2)`; the "detach into a new session"
        // model doesn't port cleanly. Require `-D` and let the shell
        // background the process (`start /B`, PowerShell `Start-Job`,
        // or a Scheduled Task / Windows service) instead.
        Err(AnvilError::invalid_config(
            "background mode is Unix-only on this build — run `gitway agent start -D` \
             and background it with `start /B`, a Scheduled Task, or a Windows service",
        ))
    }
}

/// Runs the in-process agent accept loop. Called both from `-D`
/// foreground invocations and from the post-`setsid` child we respawned.
async fn run_daemon_loop(args: &AgentStartArgs) -> Result<u32, AnvilError> {
    let socket_path = args.sock.clone().unwrap_or_else(default_socket_path);
    let pid_file = args
        .pid_file
        .clone()
        .or_else(|| default_pid_path(&socket_path));
    let default_ttl = args.default_ttl.map(Duration::from_secs);
    let cfg = AgentDaemonConfig {
        socket_path: socket_path.clone(),
        pid_file: pid_file.clone(),
        default_ttl,
    };

    // When the user wants a foreground daemon, `-D`, we also need to
    // print the eval lines here so they can `eval $(gitway agent start
    // -D -s)` inside a shell that will then keep running. The background
    // path prints the eval lines from the parent before exiting and
    // leaves stdout silent inside the detached child.
    if std::env::var_os(DAEMONIZED_MARKER).is_none() {
        emit_eval(&socket_path, std::process::id(), args.sh, args.csh);
    }

    // Drive the daemon on the outer `#[tokio::main]` runtime — nesting
    // `runtime::block_on` inside an already-running runtime panics, so
    // `.await`-ing here is the only correct option.
    daemon::run(cfg).await?;
    Ok(0)
}

/// Background-mode entry: respawn ourselves as a detached child with
/// `GITWAY_AGENT_DAEMONIZED=1` and `-D`, wait for the socket to appear,
/// then print the eval lines and exit so the calling shell can source
/// them.
///
/// # Detachment model
///
/// `std::process::Command::spawn` creates a child that inherits our
/// session but has stdio pointed at `/dev/null`. The child's `main`
/// detects `DAEMONIZED_MARKER`, calls `setsid(2)` to become a session
/// leader of a brand-new session (which has no controlling TTY), then
/// proceeds into the agent loop. Avoiding `pre_exec` keeps the entire
/// flow free of `unsafe`.
#[cfg(unix)]
fn run_background_start(args: &AgentStartArgs) -> Result<u32, AnvilError> {
    let raw_socket_path = args.sock.clone().unwrap_or_else(default_socket_path);
    // The child calls `chdir("/")` after `setsid`, so any relative path
    // we hand it would resolve under `/`. Canonicalize to an absolute
    // path before spawning. `absolute_path` avoids `std::fs::canonicalize`
    // which requires the target to already exist.
    let socket_path = absolute_path(&raw_socket_path)?;
    let pid_file = args
        .pid_file
        .as_ref()
        .map(|p| absolute_path(p))
        .transpose()?;

    // Fail fast if the path already points at a live socket — this is a
    // normal user mistake ("I already sourced gitway once in this
    // shell"), and the child would otherwise clobber it.
    if socket_path.exists() {
        return Err(AnvilError::invalid_config(format!(
            "socket {} already exists; another agent may be running. \
             Run `gitway agent stop` first, or pass a different `-a <PATH>`.",
            socket_path.display()
        )));
    }

    let exe = std::env::current_exe().map_err(|e| {
        AnvilError::invalid_config(format!("cannot locate the gitway binary for re-exec: {e}"))
    })?;

    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("agent")
        .arg("start")
        .arg("-D")
        .arg("-a")
        .arg(socket_path.as_os_str());
    if let Some(ttl) = args.default_ttl {
        cmd.arg("-t").arg(ttl.to_string());
    }
    if let Some(ref pid_path) = pid_file {
        cmd.arg("--pid-file").arg(pid_path.as_os_str());
    }
    cmd.env(DAEMONIZED_MARKER, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    let child = cmd.spawn().map_err(|e| {
        AnvilError::invalid_config(format!("failed to spawn background agent: {e}"))
    })?;
    let pid = child.id();
    // Let the handle drop; Unix drop does not reap, the daemon keeps
    // running once the grandparent (this process) exits and `init`
    // adopts it.
    drop(child);

    // Poll for socket readiness — the child binds it very early in
    // `daemon::run`. 5s is generous; bind typically completes in a few
    // ms. If it never appears the child died before binding, usually
    // because the runtime dir is wrong or the socket path is already
    // taken by another process we lost the race to above.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !socket_path.exists() {
        return Err(AnvilError::invalid_config(format!(
            "background agent did not bind {} within 5s — try \
             `gitway agent start -D` to see the underlying error",
            socket_path.display()
        )));
    }

    emit_eval(&socket_path, pid, args.sh, args.csh);
    Ok(0)
}

/// Resolves `path` to an absolute path without requiring the target to
/// exist. Needed because the detached child calls `chdir("/")`, so any
/// relative path passed from the parent's shell cwd would otherwise
/// resolve under `/` in the child.
#[cfg(unix)]
fn absolute_path(path: &Path) -> Result<std::path::PathBuf, AnvilError> {
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    let cwd = std::env::current_dir().map_err(|e| {
        AnvilError::invalid_config(format!(
            "cannot resolve {} to an absolute path: {e}",
            path.display()
        ))
    })?;
    Ok(cwd.join(path))
}

/// Called from inside the detached child before the accept loop starts.
///
/// Moves us into a brand-new session with `setsid(2)` (severing the
/// parent's controlling TTY), changes cwd to `/` so we don't pin a
/// mount point, and restricts the file-mode creation mask to 0o077 so
/// the pid file and any stray writes can't end up world-readable.
///
/// All three calls are best-effort: `setsid(2)` returns EPERM if we
/// are somehow already a process-group leader (shouldn't happen under
/// `Command::spawn`, but treating it as fatal would wedge the daemon
/// for no benefit — binding the socket is what matters), and `chdir`
/// failing only means logs attach to the caller's cwd.
#[cfg(unix)]
fn finalize_detach() {
    use nix::sys::stat::{umask, Mode};
    use nix::unistd::{chdir, setsid};
    let _ = setsid();
    let _ = chdir("/");
    let _old = umask(Mode::from_bits_truncate(0o077));
}

#[cfg(unix)]
fn run_stop(args: &AgentStopArgs, mode: OutputMode) -> Result<u32, AnvilError> {
    let pid = resolve_daemon_pid(args.pid_file.as_deref())?;
    // SIGTERM for graceful shutdown; the daemon unlinks the socket and
    // pid file in its drop path.
    kill(Pid::from_raw(pid), Signal::SIGTERM)
        .map_err(|e| AnvilError::invalid_config(format!("failed to signal pid {pid}: {e}")))?;

    match mode {
        OutputMode::Json => {
            emit_json(&serde_json::json!({
                "metadata": {
                    "tool": "gitway",
                    "version": env!("CARGO_PKG_VERSION"),
                    "command": "gitway agent stop",
                    "timestamp": now_iso8601(),
                },
                "data": { "signalled_pid": pid }
            }));
        }
        OutputMode::Human => {
            eprintln!("gitway: SIGTERM sent to pid {pid}");
        }
    }
    Ok(0)
}

#[cfg(not(unix))]
fn run_stop(_args: &AgentStopArgs, _mode: OutputMode) -> Result<u32, AnvilError> {
    // Windows has no `SIGTERM` — console apps receive `CTRL_C_EVENT`
    // only from their own console, and service control is out of scope
    // for v0.6.x. Users running `gitway agent start -D` in a foreground
    // console stop it with Ctrl+C; anything else should wrap the
    // process in a launcher that knows how to terminate it (Task
    // Manager, `Stop-Process` in PowerShell, or a Windows service
    // harness).
    Err(AnvilError::invalid_config(
        "`gitway agent stop` is Unix-only — on Windows stop the agent via Ctrl+C, \
         `Stop-Process -Id <pid>` in PowerShell, or your service harness",
    ))
}

#[cfg(unix)]
fn resolve_daemon_pid(cli_pid_file: Option<&Path>) -> Result<i32, AnvilError> {
    if let Ok(s) = std::env::var("SSH_AGENT_PID") {
        return s.trim().parse().map_err(|_e: std::num::ParseIntError| {
            AnvilError::invalid_config(format!("SSH_AGENT_PID is not an integer: {s:?}"))
        });
    }
    let path = cli_pid_file
        .map(Path::to_owned)
        .or_else(|| default_pid_path(&default_socket_path()))
        .ok_or_else(|| {
            AnvilError::invalid_config(
                "no running agent to stop: neither SSH_AGENT_PID nor a \
                 pid file are available",
            )
        })?;
    let contents = fs::read_to_string(&path)?;
    contents
        .trim()
        .parse::<i32>()
        .map_err(|_e: std::num::ParseIntError| {
            AnvilError::invalid_config(format!(
                "pid file {} does not contain a valid integer",
                path.display()
            ))
        })
}

/// Emits `ssh-agent -s` / `-c` compatible shell eval lines to stdout.
fn emit_eval(socket_path: &Path, pid: u32, bourne: bool, csh_forced: bool) {
    let csh = csh_forced
        || (!bourne
            && std::env::var("SHELL")
                .ok()
                .as_deref()
                .is_some_and(|sh| sh.ends_with("csh") || sh.ends_with("tcsh")));
    if csh {
        println!("setenv SSH_AUTH_SOCK {};", socket_path.display());
        println!("setenv SSH_AGENT_PID {pid};");
        println!("echo Agent pid {pid};");
    } else {
        println!(
            "SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;",
            socket_path.display()
        );
        println!("SSH_AGENT_PID={pid}; export SSH_AGENT_PID;");
        println!("echo Agent pid {pid};");
    }
}

/// Default socket location.
///
/// - **Unix**: `$XDG_RUNTIME_DIR/gitway-agent.<PID>.sock` when the
///   runtime dir is set, otherwise a 0700 `$TMPDIR/gitway-agent-<user>/
///   agent.<PID>` fallback.
/// - **Windows**: `\\.\pipe\gitway-agent.<PID>` — a named pipe under
///   the standard local pipe namespace. Windows has no `$XDG_RUNTIME_DIR`
///   equivalent, and the default ACL on `CreatePipe` already restricts
///   access to the creating user's SID.
fn default_socket_path() -> std::path::PathBuf {
    let pid = std::process::id();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
            return std::path::PathBuf::from(runtime).join(format!("gitway-agent.{pid}.sock"));
        }
        let tmp = std::env::var("TMPDIR").unwrap_or_else(|_e| "/tmp".to_owned());
        let user = std::env::var("USER").unwrap_or_else(|_e| "default".to_owned());
        let parent = std::path::PathBuf::from(tmp).join(format!("gitway-agent-{user}"));
        let _ = fs::create_dir_all(&parent);
        let _ = fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700));
        parent.join(format!("agent.{pid}"))
    }
    #[cfg(not(unix))]
    {
        std::path::PathBuf::from(format!(r"\\.\pipe\gitway-agent.{pid}"))
    }
}

/// Default pid-file path that sits next to the socket on Unix. On
/// Windows we never write a pid file by default — named pipes have no
/// filesystem parent, and `gitway agent stop` is Unix-only anyway.
fn default_pid_path(socket_path: &Path) -> Option<std::path::PathBuf> {
    #[cfg(unix)]
    {
        socket_path.parent().map(|p| p.join("gitway-agent.pid"))
    }
    #[cfg(not(unix))]
    {
        let _ = socket_path;
        None
    }
}
