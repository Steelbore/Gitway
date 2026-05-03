// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration tests for `gitway-add` (and transitively
//! `anvil_ssh::agent::client::Agent`).
//!
//! Strategy: spawn OpenSSH's `ssh-agent -D -a <tmp>` as a subprocess,
//! point `$SSH_AUTH_SOCK` at its socket, then drive the shim through the
//! ssh-add workflow:
//!
//! 1. Add a freshly generated Ed25519 key (no passphrase) via
//!    `gitway-add <path>`.
//! 2. `gitway-add -l` lists exactly one identity with the expected
//!    fingerprint.
//! 3. `gitway-add -d <path>` removes it.
//! 4. `gitway-add -l` reports "no identities" (exit 1).
//!
//! The test is `#[ignore]` by default because it requires OpenSSH's
//! `ssh-agent` on `$PATH`. Run explicitly with:
//!
//! ```sh
//! cargo test -p gitway --test agent_client -- --ignored
//! ```

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn gitway_keygen() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gitway-keygen"))
}

fn gitway_add() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gitway-add"))
}

fn find_ssh_agent() -> Option<PathBuf> {
    let output = Command::new("sh")
        .args(["-c", "command -v ssh-agent"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8(output.stdout).ok()?;
    let trimmed = path.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

/// Spawns `ssh-agent -D -a <sock>` and waits for the socket to appear.
struct Agent {
    process: Child,
    sock: PathBuf,
}

impl Agent {
    fn spawn(dir: &TempDir) -> Option<Self> {
        let openssh = find_ssh_agent()?;
        let sock = dir.path().join("agent.sock");
        let mut process = Command::new(&openssh)
            .args(["-D", "-a"])
            .arg(&sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn ssh-agent");
        let deadline = Instant::now() + Duration::from_secs(3);
        while !sock.exists() {
            if Instant::now() >= deadline {
                let _ = process.kill();
                let _ = process.wait();
                return None;
            }
            thread::sleep(Duration::from_millis(50));
        }
        Some(Self { process, sock })
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = fs::remove_file(&self.sock);
    }
}

#[test]
#[ignore = "requires OpenSSH `ssh-agent` on PATH"]
fn add_list_remove_roundtrip() {
    let dir = TempDir::new().unwrap();
    let Some(agent) = Agent::spawn(&dir) else {
        eprintln!("skipping: no ssh-agent on PATH or agent failed to start");
        return;
    };

    // 1. Generate a throwaway key.
    let key_path = dir.path().join("k");
    let gen_output = Command::new(gitway_keygen())
        .args([
            "-t",
            "ed25519",
            "-f",
            key_path.to_str().unwrap(),
            "-N",
            "",
            "-C",
            "gitway-agent-test",
        ])
        .output()
        .unwrap();
    assert!(gen_output.status.success());

    // 2. Add via gitway-add.
    let add_output = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &agent.sock)
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "gitway-add failed: stderr={:?}",
        String::from_utf8_lossy(&add_output.stderr),
    );

    // 3. List — must show exactly one entry.
    let list_output = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &agent.sock)
        .arg("-l")
        .output()
        .unwrap();
    assert!(list_output.status.success());
    let listed = String::from_utf8_lossy(&list_output.stdout);
    assert!(
        listed.lines().count() == 1,
        "expected exactly 1 identity, got:\n{listed}"
    );
    assert!(
        listed.contains("SHA256:"),
        "missing SHA256 prefix: {listed}"
    );

    // 4. Remove by public-key path.
    let rm_output = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &agent.sock)
        .args(["-d"])
        .arg(key_path.with_extension("pub"))
        .output()
        .unwrap();
    assert!(
        rm_output.status.success(),
        "gitway-add -d failed: stderr={:?}",
        String::from_utf8_lossy(&rm_output.stderr),
    );

    // 5. List — empty agent prints the "no identities" message and
    //    exits non-zero (matches ssh-add).
    let empty = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &agent.sock)
        .arg("-l")
        .output()
        .unwrap();
    assert_eq!(empty.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&empty.stdout);
    assert!(
        stdout.to_ascii_lowercase().contains("no identities"),
        "unexpected output: {stdout}"
    );
}

#[test]
#[ignore = "requires OpenSSH `ssh-agent` on PATH"]
fn remove_all_empties_agent() {
    let dir = TempDir::new().unwrap();
    let Some(agent) = Agent::spawn(&dir) else {
        eprintln!("skipping: no ssh-agent on PATH");
        return;
    };

    // Generate + add two keys.
    for name in ["a", "b"] {
        let key_path = dir.path().join(name);
        let _ = Command::new(gitway_keygen())
            .args(["-t", "ed25519", "-f", key_path.to_str().unwrap(), "-N", ""])
            .output()
            .unwrap();
        let add_output = Command::new(gitway_add())
            .env("SSH_AUTH_SOCK", &agent.sock)
            .arg(&key_path)
            .output()
            .unwrap();
        assert!(add_output.status.success());
    }

    // Remove all.
    let rm_output = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &agent.sock)
        .arg("-D")
        .output()
        .unwrap();
    assert!(rm_output.status.success());

    // List must be empty now.
    let empty = Command::new(gitway_add())
        .env("SSH_AUTH_SOCK", &agent.sock)
        .arg("-l")
        .output()
        .unwrap();
    assert_eq!(empty.status.code(), Some(1));
}
