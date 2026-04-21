// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration tests for the `gitway agent start` daemon (Phase 3).
//!
//! Strategy: spawn `gitway agent start -D -s -a <tmp>` as a subprocess,
//! wait for the socket to appear, then drive the full lifecycle through
//! `gitway-add`:
//!
//! 1. Generate a fresh Ed25519 key (unencrypted).
//! 2. `gitway-add <k>` — add it.
//! 3. `gitway-add -l` — list shows exactly one entry with the expected fingerprint.
//! 4. `gitway-add -D` — remove all.
//! 5. `gitway-add -l` — empty; exit 1.
//! 6. SIGTERM the daemon; socket must be gone.
//!
//! Unix-only. The test runs by default (no `#[ignore]`) because it
//! relies only on Gitway's own binaries — no OpenSSH required.

#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tempfile::TempDir;

fn gitway() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gitway"))
}

fn gitway_keygen() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gitway-keygen"))
}

fn gitway_add() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gitway-add"))
}

/// Spawns `gitway agent start -D -s -a <dir>/agent.sock` and waits until
/// the socket appears.
struct Daemon {
    process: Child,
    sock: PathBuf,
}

impl Daemon {
    fn spawn(dir: &TempDir) -> Self {
        Self::spawn_with_env(dir, &[])
    }

    /// Like [`spawn`], but lets the test inject extra environment
    /// variables into the daemon process. Used by the confirm-flow
    /// tests to pre-wire `SSH_ASKPASS` to a deterministic shell
    /// script so the daemon's askpass path exercises the full
    /// spawn + exit-status round-trip.
    fn spawn_with_env(dir: &TempDir, env: &[(&str, &std::ffi::OsStr)]) -> Self {
        let sock = dir.path().join("agent.sock");
        let mut cmd = Command::new(gitway());
        cmd.args(["agent", "start", "-D", "-s", "-a"])
            .arg(&sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let process = cmd.spawn().expect("failed to spawn gitway agent start");
        let deadline = Instant::now() + Duration::from_secs(3);
        while !sock.exists() {
            assert!(
                Instant::now() < deadline,
                "agent socket did not appear at {} within 3s",
                sock.display()
            );
            thread::sleep(Duration::from_millis(50));
        }
        Self { process, sock }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // SIGTERM the daemon so its shutdown path unlinks the socket.
        if let Ok(p) = i32::try_from(self.process.id()) {
            let _ = kill(Pid::from_raw(p), Signal::SIGTERM);
        }
        let _ = self.process.wait();
        // Belt-and-braces: remove the socket if the daemon didn't.
        let _ = fs::remove_file(&self.sock);
    }
}

#[test]
fn daemon_lifecycle_add_list_remove() {
    let dir = TempDir::new().unwrap();
    let daemon = Daemon::spawn(&dir);

    // 1. Generate a throwaway key.
    let key_path = dir.path().join("k");
    let gen_output = Command::new(gitway_keygen())
        .args(["-t", "ed25519", "-f", key_path.to_str().unwrap(), "-N", ""])
        .output()
        .unwrap();
    assert!(gen_output.status.success());

    // 2. Add.
    let add_output = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &daemon.sock)
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "gitway-add failed: stderr={:?}",
        String::from_utf8_lossy(&add_output.stderr),
    );

    // 3. List — exactly one entry.
    let list_output = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &daemon.sock)
        .arg("-l")
        .output()
        .unwrap();
    assert!(list_output.status.success());
    let listed = String::from_utf8_lossy(&list_output.stdout);
    assert_eq!(
        listed.lines().count(),
        1,
        "expected 1 identity, got:\n{listed}"
    );
    assert!(listed.contains("SHA256:"));

    // 4. Remove all.
    let rm_output = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &daemon.sock)
        .arg("-D")
        .output()
        .unwrap();
    assert!(rm_output.status.success());

    // 5. List — empty (exit 1, matches ssh-add).
    let empty = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &daemon.sock)
        .arg("-l")
        .output()
        .unwrap();
    assert_eq!(empty.status.code(), Some(1));

    // Drop(daemon) signals SIGTERM; assert the socket is gone afterward.
    let sock_path = daemon.sock.clone();
    drop(daemon);
    let deadline = Instant::now() + Duration::from_secs(2);
    while sock_path.exists() {
        assert!(
            Instant::now() < deadline,
            "socket {} was not unlinked after SIGTERM",
            sock_path.display()
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn daemon_background_mode_detaches_and_advertises_pid() {
    // Background mode (no `-D`): `gitway agent start` respawns itself
    // as a detached child, prints eval lines to stdout, and exits. The
    // child is adopted by `init`, runs in its own session, and keeps
    // serving requests.
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("bg-agent.sock");
    let pid_file = dir.path().join("bg-agent.pid");

    let output = Command::new(gitway())
        .args(["agent", "start", "-s", "-a"])
        .arg(&sock)
        .arg("--pid-file")
        .arg(&pid_file)
        .output()
        .expect("spawn gitway agent start (background)");
    assert!(
        output.status.success(),
        "background start failed: stderr={:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Parse the daemon PID out of the eval lines (Bourne shell format).
    let stdout = String::from_utf8_lossy(&output.stdout);
    let daemon_pid = parse_ssh_agent_pid(&stdout)
        .unwrap_or_else(|| panic!("no SSH_AGENT_PID in eval output:\n{stdout}"));

    // Track cleanup: always kill the daemon by PID so a failed assertion
    // doesn't leak a background process.
    let _guard = Kill(daemon_pid, sock.clone());

    // Socket must already exist — the parent blocks until bind completes.
    assert!(
        sock.exists(),
        "socket {} not present after background start returned",
        sock.display()
    );
    // Pid file wired up via `--pid-file`.
    assert!(
        pid_file.exists(),
        "pid file {} not written",
        pid_file.display()
    );
    let pid_file_contents: i32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .expect("pid file contains valid integer");
    assert_eq!(pid_file_contents, daemon_pid);

    // The detached daemon must not be a descendant of this test process.
    // Assert its ppid is 1 (reparented to init) — proves setsid + detach
    // actually severed the parent link.
    let ppid = read_ppid(daemon_pid).expect("read /proc ppid");
    assert_eq!(
        ppid, 1,
        "background agent pid {daemon_pid} was not reparented to init (ppid={ppid})"
    );

    // Sanity: add + list works through it, proving the socket and the
    // post-setsid tokio runtime are both healthy.
    let key_path = dir.path().join("k");
    Command::new(gitway_keygen())
        .args(["-t", "ed25519", "-f", key_path.to_str().unwrap(), "-N", ""])
        .output()
        .unwrap();
    let add = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &sock)
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(add.status.success());
    let list = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &sock)
        .arg("-l")
        .output()
        .unwrap();
    assert!(list.status.success());

    // Clean shutdown via `gitway agent stop` (reads the pid file).
    let stop = Command::new(gitway())
        .args(["agent", "stop", "--pid-file"])
        .arg(&pid_file)
        .env_remove("SSH_AGENT_PID")
        .output()
        .unwrap();
    assert!(
        stop.status.success(),
        "stop failed: stderr={:?}",
        String::from_utf8_lossy(&stop.stderr)
    );

    let deadline = Instant::now() + Duration::from_secs(2);
    while sock.exists() {
        assert!(
            Instant::now() < deadline,
            "socket {} not unlinked after stop",
            sock.display()
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn daemon_background_mode_rejects_existing_socket() {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("taken.sock");
    // Create a dummy file where the socket would go — parent should
    // detect the collision and bail out before respawning.
    fs::write(&sock, b"").unwrap();

    let output = Command::new(gitway())
        .args(["agent", "start", "-s", "-a"])
        .arg(&sock)
        .output()
        .expect("spawn gitway agent start");
    assert!(
        !output.status.success(),
        "expected failure, got success; stdout={:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already exists"),
        "expected collision error, got: {stderr}"
    );
}

/// Drop guard that kills the background daemon by PID even when the
/// test fails partway through — a leaked detached process would
/// otherwise outlive `cargo test`.
struct Kill(i32, PathBuf);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = kill(Pid::from_raw(self.0), Signal::SIGTERM);
        let _ = fs::remove_file(&self.1);
    }
}

fn parse_ssh_agent_pid(eval_lines: &str) -> Option<i32> {
    // Matches `SSH_AGENT_PID=12345;` from the Bourne eval output.
    for line in eval_lines.lines() {
        let Some(rest) = line.trim().strip_prefix("SSH_AGENT_PID=") else {
            continue;
        };
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        return digits.parse().ok();
    }
    None
}

#[cfg(target_os = "linux")]
fn read_ppid(pid: i32) -> Option<i32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn read_ppid(pid: i32) -> Option<i32> {
    // `ps -o ppid= -p <pid>` works on macOS; CI matrix is Linux and
    // macOS only, Windows is gated out by `#![cfg(unix)]`.
    let out = Command::new("ps")
        .args(["-o", "ppid=", "-p"])
        .arg(pid.to_string())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[test]
fn daemon_ttl_expires_identity() {
    let dir = TempDir::new().unwrap();
    let daemon = Daemon::spawn(&dir);

    let key_path = dir.path().join("k");
    let _ = Command::new(gitway_keygen())
        .args(["-t", "ed25519", "-f", key_path.to_str().unwrap(), "-N", ""])
        .output()
        .unwrap();

    // Add with a 1-second lifetime.
    let add_output = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &daemon.sock)
        .args(["-t", "1"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(add_output.status.success());

    // Wait for the daemon's eviction sweeper to run (ticks once per
    // second).
    thread::sleep(Duration::from_millis(2_500));

    let empty = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &daemon.sock)
        .arg("-l")
        .output()
        .unwrap();
    assert_eq!(
        empty.status.code(),
        Some(1),
        "identity should have been evicted; list output was: {}",
        String::from_utf8_lossy(&empty.stdout)
    );
}

// ── Confirm flow (SSH_ASKPASS round-trip) ─────────────────────────────

/// Creates an executable shell script in `dir` that exits with
/// `exit_code`. Used as a scripted askpass to drive the daemon's
/// confirm path deterministically.
fn write_askpass_script(dir: &TempDir, name: &str, exit_code: i32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.path().join(name);
    fs::write(&path, format!("#!/bin/sh\nexit {exit_code}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Issues an SSH agent sign request for `key` over `sock` using
/// `ssh-agent-lib`'s blocking client, bypassing `gitway-add` (which
/// has no CLI sign verb). Returns `Ok` on approval, `Err` on denial.
fn agent_sign_via_wire(
    sock: &std::path::Path,
    key: &ssh_key::PrivateKey,
) -> Result<ssh_key::Signature, ssh_agent_lib::error::AgentError> {
    use ssh_agent_lib::blocking::Client;
    use ssh_agent_lib::proto::SignRequest;
    let stream = std::os::unix::net::UnixStream::connect(sock).expect("connect agent socket");
    let mut client = Client::new(stream);
    client.sign(SignRequest {
        pubkey: key.public_key().key_data().clone(),
        data: b"gitway-agent-confirm-test".to_vec(),
        flags: 0,
    })
}

#[test]
fn daemon_confirm_allows_sign_when_askpass_approves() {
    let dir = TempDir::new().unwrap();
    let askpass = write_askpass_script(&dir, "yes.sh", 0);
    let daemon = Daemon::spawn_with_env(&dir, &[("SSH_ASKPASS", askpass.as_os_str())]);

    // Generate + load a key with the `--confirm` constraint.
    let key_path = dir.path().join("k");
    Command::new(gitway_keygen())
        .args(["-t", "ed25519", "-f", key_path.to_str().unwrap(), "-N", ""])
        .output()
        .unwrap();
    let add = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &daemon.sock)
        .arg("-c")
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(
        add.status.success(),
        "gitway-add -c failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let key = ssh_key::PrivateKey::from_openssh(fs::read_to_string(&key_path).unwrap()).unwrap();
    let sig = agent_sign_via_wire(&daemon.sock, &key)
        .expect("sign request should have been approved via askpass");
    assert_eq!(sig.algorithm(), ssh_key::Algorithm::Ed25519);
}

#[test]
fn daemon_confirm_refuses_sign_when_askpass_denies() {
    let dir = TempDir::new().unwrap();
    let askpass = write_askpass_script(&dir, "no.sh", 1);
    let daemon = Daemon::spawn_with_env(&dir, &[("SSH_ASKPASS", askpass.as_os_str())]);

    let key_path = dir.path().join("k");
    Command::new(gitway_keygen())
        .args(["-t", "ed25519", "-f", key_path.to_str().unwrap(), "-N", ""])
        .output()
        .unwrap();
    Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &daemon.sock)
        .arg("-c")
        .arg(&key_path)
        .output()
        .unwrap();

    let key = ssh_key::PrivateKey::from_openssh(fs::read_to_string(&key_path).unwrap()).unwrap();
    let err = agent_sign_via_wire(&daemon.sock, &key)
        .expect_err("denied askpass must translate to an agent sign failure");
    // The daemon returns `SSH_AGENT_FAILURE` on the wire. The blocking
    // client surfaces that as either `AgentError::Failure` or
    // `Proto(UnexpectedResponse)` (since the client only pattern-matches
    // on `SignResponse` and wraps everything else). Either shape is a
    // legitimate sign denial — the important thing is it wasn't an
    // `Ok(sig)`.
    assert_sign_denied(&err);
}

#[test]
fn daemon_confirm_refuses_sign_when_ssh_askpass_unset() {
    // Fail-safe: no SSH_ASKPASS in the daemon's env at all. The daemon
    // must reject the sign request rather than falling through to the
    // signer as if the key were not `--confirm`-constrained.
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("agent.sock");
    let mut cmd = Command::new(gitway());
    cmd.args(["agent", "start", "-D", "-s", "-a"])
        .arg(&sock)
        .env_remove("SSH_ASKPASS")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let process = cmd.spawn().unwrap();
    let daemon = Daemon { process, sock };
    let deadline = Instant::now() + Duration::from_secs(3);
    while !daemon.sock.exists() {
        assert!(Instant::now() < deadline, "socket never appeared");
        thread::sleep(Duration::from_millis(50));
    }

    let key_path = dir.path().join("k");
    Command::new(gitway_keygen())
        .args(["-t", "ed25519", "-f", key_path.to_str().unwrap(), "-N", ""])
        .output()
        .unwrap();
    Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &daemon.sock)
        .arg("-c")
        .arg(&key_path)
        .output()
        .unwrap();

    let key = ssh_key::PrivateKey::from_openssh(fs::read_to_string(&key_path).unwrap()).unwrap();
    let err = agent_sign_via_wire(&daemon.sock, &key)
        .expect_err("missing askpass must fail-safe to a sign denial");
    assert_sign_denied(&err);
}

/// Shared assertion for confirm-path denial tests.
///
/// The daemon answers an unauthorized sign request with
/// `SSH_AGENT_FAILURE`. `ssh-agent-lib`'s blocking client only
/// unwraps `Response::SignResponse`, so it surfaces every other
/// response — `Failure` included — as `Proto(UnexpectedResponse)`.
/// Either shape counts as a legitimate denial; we just want to
/// reject silent fall-throughs where the signer ran anyway.
fn assert_sign_denied(err: &ssh_agent_lib::error::AgentError) {
    use ssh_agent_lib::error::AgentError;
    use ssh_agent_lib::proto::ProtoError;
    let ok = matches!(err, AgentError::Failure)
        || matches!(err, AgentError::Proto(ProtoError::UnexpectedResponse));
    assert!(ok, "expected sign denial, got: {err:?}");
}
