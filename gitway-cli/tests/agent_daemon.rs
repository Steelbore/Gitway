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
        let sock = dir.path().join("agent.sock");
        let process = Command::new(gitway())
            .args(["agent", "start", "-D", "-s", "-a"])
            .arg(&sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn gitway agent start");
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
