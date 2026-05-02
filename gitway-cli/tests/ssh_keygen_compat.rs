// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration tests for the `gitway-keygen` ssh-keygen-compat shim.
//!
//! These tests invoke the compiled binary as a subprocess (Cargo provides
//! the path via `CARGO_BIN_EXE_gitway-keygen`) and assert that:
//!
//! 1. `gitway-keygen -t ed25519 -f <tmp> -N ''` produces a valid OpenSSH
//!    keypair that `ssh-keygen -lf` recognises — when the real
//!    `ssh-keygen` is available on `$PATH`. This is the cross-compat
//!    guarantee we care about most: GitHub's verify path reads the
//!    public key exactly as OpenSSH writes it.
//! 2. `gitway-keygen -Y sign -n git -f <key>` writes an armored SSHSIG
//!    to stdout that `gitway-keygen -Y check-novalidate` accepts. This
//!    is hermetic (no network, no OpenSSH dependency) and runs
//!    unconditionally.
//! 3. `gitway-keygen -Y check-novalidate` rejects a signature over
//!    tampered data with exit 4.
//!
//! Tests marked `#[ignore]` are opt-in (`cargo test -- --ignored`) and
//! require either network access or a locally installed OpenSSH
//! `ssh-keygen`. The hermetic roundtrip (test 2 and 3) runs by default.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use tempfile::TempDir;

/// Returns the absolute path to the compiled `gitway-keygen` binary.
///
/// Cargo sets this env var at compile time for integration tests in the
/// crate that produces the binary. See the reference docs:
/// <https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-crates>
fn gitway_keygen() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gitway-keygen"))
}

/// Generates an Ed25519 keypair at `<dir>/k` with an empty passphrase and
/// returns the private-key path.
fn generate_test_key(dir: &TempDir) -> PathBuf {
    let key_path = dir.path().join("k");
    let output = Command::new(gitway_keygen())
        .args([
            "-t",
            "ed25519",
            "-f",
            key_path.to_str().unwrap(),
            "-N",
            "",
            "-C",
            "gitway-compat@test",
        ])
        .output()
        .expect("failed to run gitway-keygen");
    assert!(
        output.status.success(),
        "gitway-keygen generate failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        key_path.exists(),
        "expected private key at {}",
        key_path.display()
    );
    assert!(
        key_path.with_extension("pub").exists(),
        "expected public key at {}.pub",
        key_path.display()
    );
    key_path
}

/// Signs `payload` with `key_path` under `namespace` and writes the armored
/// SSHSIG to `sig_path`.  Used by the verify-mode tests below.
fn sign_to_file(key_path: &Path, namespace: &str, payload: &[u8], sig_path: &Path) {
    let mut child = Command::new(gitway_keygen())
        .args([
            "-Y",
            "sign",
            "-n",
            namespace,
            "-f",
            key_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn gitway-keygen -Y sign");
    child.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let output = child.wait_with_output().expect("sign subprocess failed");
    assert!(
        output.status.success(),
        "sign failed: stderr={:?}",
        String::from_utf8_lossy(&output.stderr),
    );
    fs::write(sig_path, &output.stdout).unwrap();
}

/// Writes a single-entry `allowed_signers` file authorizing `principal` to
/// sign under `namespaces` (e.g. `"git"`) with the public key at `pub_path`.
fn write_allowed_signers_for(
    pub_path: &Path,
    principal: &str,
    namespaces: &str,
    allowed_path: &Path,
) {
    let pub_line = fs::read_to_string(pub_path).expect("read pub key");
    let trimmed = pub_line.trim();
    let mut parts = trimmed.splitn(3, char::is_whitespace);
    let key_type = parts.next().expect("pub line has key type");
    let key_b64 = parts.next().expect("pub line has key blob");
    let line = format!("{principal} namespaces=\"{namespaces}\" {key_type} {key_b64}\n");
    fs::write(allowed_path, line).unwrap();
}

// ── Hermetic tests (always run) ──────────────────────────────────────────────

#[test]
fn sign_then_check_novalidate_roundtrip() {
    let dir = TempDir::new().unwrap();
    let key_path = generate_test_key(&dir);
    let payload = b"the quick brown fox jumps over the lazy dog";

    // Sign stdin → armored signature on stdout.
    let mut child = Command::new(gitway_keygen())
        .args(["-Y", "sign", "-n", "git", "-f", key_path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn gitway-keygen -Y sign");
    child.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let sign_output = child.wait_with_output().expect("sign subprocess failed");
    assert!(
        sign_output.status.success(),
        "sign failed: stderr={:?}",
        String::from_utf8_lossy(&sign_output.stderr),
    );
    let armored = String::from_utf8(sign_output.stdout).expect("sig is UTF-8");
    assert!(
        armored.starts_with("-----BEGIN SSH SIGNATURE-----"),
        "expected armored SSHSIG, got {armored:?}"
    );

    // Write the signature to a file and verify it via check-novalidate.
    let sig_path = dir.path().join("sig");
    fs::write(&sig_path, &armored).unwrap();

    let mut child = Command::new(gitway_keygen())
        .args([
            "-Y",
            "check-novalidate",
            "-n",
            "git",
            "-s",
            sig_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let verify_output = child.wait_with_output().unwrap();
    assert!(
        verify_output.status.success(),
        "verify failed: stderr={:?}",
        String::from_utf8_lossy(&verify_output.stderr),
    );
}

#[test]
fn tampered_payload_is_rejected() {
    let dir = TempDir::new().unwrap();
    let key_path = generate_test_key(&dir);

    // Sign the original payload.
    let mut child = Command::new(gitway_keygen())
        .args(["-Y", "sign", "-n", "git", "-f", key_path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"original")
        .unwrap();
    let sign_output = child.wait_with_output().unwrap();
    assert!(sign_output.status.success());
    let sig_path = dir.path().join("sig");
    fs::write(&sig_path, sign_output.stdout).unwrap();

    // Try to verify against a different payload — must fail.
    let mut child = Command::new(gitway_keygen())
        .args([
            "-Y",
            "check-novalidate",
            "-n",
            "git",
            "-s",
            sig_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"tampered")
        .unwrap();
    let verify_output = child.wait_with_output().unwrap();
    assert!(
        !verify_output.status.success(),
        "verify should have failed for tampered data"
    );
    // Exit code should map to SignatureInvalid (4) per the SFRS table.
    assert_eq!(verify_output.status.code(), Some(4));
}

#[test]
fn namespace_mismatch_is_rejected() {
    let dir = TempDir::new().unwrap();
    let key_path = generate_test_key(&dir);

    let mut child = Command::new(gitway_keygen())
        .args(["-Y", "sign", "-n", "git", "-f", key_path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"payload").unwrap();
    let sign_output = child.wait_with_output().unwrap();
    assert!(sign_output.status.success());
    let sig_path = dir.path().join("sig");
    fs::write(&sig_path, sign_output.stdout).unwrap();

    // Verify with wrong namespace → fails.
    let mut child = Command::new(gitway_keygen())
        .args([
            "-Y",
            "check-novalidate",
            "-n",
            "file",
            "-s",
            sig_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"payload").unwrap();
    let verify_output = child.wait_with_output().unwrap();
    assert!(!verify_output.status.success());
}

// ── Packed and separated `-O` option compat (always run) ────────────────────
//
// Git for Windows 2.45+ passes `-Overify-time=YYYYMMDDHHMMSS` (packed form,
// single argv token) to the `gpg.ssh.program` binary during signature
// verification.  Older Git versions and `ssh-keygen -Y sign` use the
// separated form `-O verify-time=…`.  Both must parse and be ignored —
// Gitway has no allowed-signers time-bound enforcement, so option semantics
// are deferred.

#[test]
#[allow(non_snake_case)]
fn check_novalidate_accepts_packed_O_verify_time() {
    let dir = TempDir::new().unwrap();
    let key_path = generate_test_key(&dir);
    let sig_path = dir.path().join("sig");
    let payload = b"packed-O check-novalidate";
    sign_to_file(&key_path, "git", payload, &sig_path);

    let mut child = Command::new(gitway_keygen())
        .args([
            "-Y",
            "check-novalidate",
            "-n",
            "git",
            "-s",
            sig_path.to_str().unwrap(),
            "-Overify-time=20260502133530",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "check-novalidate exit={:?}, stderr={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Good \"git\" signature"),
        "unexpected stdout: {stdout:?}"
    );
}

#[test]
#[allow(non_snake_case)]
fn check_novalidate_accepts_separated_O_value_for_compat() {
    let dir = TempDir::new().unwrap();
    let key_path = generate_test_key(&dir);
    let sig_path = dir.path().join("sig");
    let payload = b"separated-O regression guard";
    sign_to_file(&key_path, "git", payload, &sig_path);

    let mut child = Command::new(gitway_keygen())
        .args([
            "-Y",
            "check-novalidate",
            "-n",
            "git",
            "-s",
            sig_path.to_str().unwrap(),
            "-O",
            "verify-time=20260502133530",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "check-novalidate (separated -O) exit={:?}, stderr={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
#[allow(non_snake_case)]
fn find_principals_accepts_packed_O_verify_time() {
    let dir = TempDir::new().unwrap();
    let key_path = generate_test_key(&dir);
    let pub_path = key_path.with_extension("pub");
    let sig_path = dir.path().join("sig");
    let allowed_path = dir.path().join("allowed_signers");
    let payload = b"find-principals packed-O baseline";

    sign_to_file(&key_path, "git", payload, &sig_path);
    write_allowed_signers_for(&pub_path, "user@example.com", "git", &allowed_path);

    let output = Command::new(gitway_keygen())
        .args([
            "-Y",
            "find-principals",
            "-n",
            "git",
            "-s",
            sig_path.to_str().unwrap(),
            "-f",
            allowed_path.to_str().unwrap(),
            "-Overify-time=20260502133530",
        ])
        .output()
        .expect("failed to spawn gitway-keygen -Y find-principals");
    assert!(
        output.status.success(),
        "find-principals exit={:?}, stderr={:?}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("user@example.com"),
        "expected principal in stdout, got {stdout:?}"
    );
}

#[test]
#[allow(non_snake_case)]
fn verify_accepts_packed_O_verify_time() {
    let dir = TempDir::new().unwrap();
    let key_path = generate_test_key(&dir);
    let pub_path = key_path.with_extension("pub");
    let sig_path = dir.path().join("sig");
    let allowed_path = dir.path().join("allowed_signers");
    let payload = b"verify packed-O baseline";

    sign_to_file(&key_path, "git", payload, &sig_path);
    write_allowed_signers_for(&pub_path, "user@example.com", "git", &allowed_path);

    let mut child = Command::new(gitway_keygen())
        .args([
            "-Y",
            "verify",
            "-n",
            "git",
            "-I",
            "user@example.com",
            "-s",
            sig_path.to_str().unwrap(),
            "-f",
            allowed_path.to_str().unwrap(),
            "-Overify-time=20260502133530",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "verify exit={:?}, stderr={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Good \"git\" signature"),
        "expected Good signature line, got {stdout:?}"
    );
    assert!(
        stdout.contains("user@example.com"),
        "expected signer identity in stdout, got {stdout:?}"
    );
}

// ── Opt-in cross-check against real ssh-keygen (requires OpenSSH) ────────────

/// Returns `Some(path)` if the real `ssh-keygen` is on `$PATH`.
fn find_ssh_keygen() -> Option<PathBuf> {
    let output = Command::new("sh")
        .args(["-c", "command -v ssh-keygen"])
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

/// Cross-checks that a key generated by `gitway-keygen` is parsed correctly
/// by OpenSSH's `ssh-keygen -lf`.
///
/// Marked `#[ignore]` because it requires OpenSSH on the test machine.
/// Run explicitly with:
///
/// ```sh
/// cargo test -p gitway --test ssh_keygen_compat -- --ignored
/// ```
#[test]
#[ignore = "requires OpenSSH `ssh-keygen` on PATH"]
fn openssh_can_read_our_public_key() {
    let Some(openssh) = find_ssh_keygen() else {
        eprintln!("skipping: no ssh-keygen on PATH");
        return;
    };
    let dir = TempDir::new().unwrap();
    let key_path = generate_test_key(&dir);
    let pub_path = key_path.with_extension("pub");

    let output = Command::new(&openssh)
        .args(["-l", "-f"])
        .arg(&pub_path)
        .output()
        .expect("failed to run ssh-keygen -lf");
    assert!(
        output.status.success(),
        "ssh-keygen -lf failed: stderr={:?}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("SHA256:"),
        "ssh-keygen output lacks SHA256 fingerprint: {stdout:?}"
    );
    assert!(
        stdout.contains("ED25519"),
        "ssh-keygen output lacks ED25519 algorithm: {stdout:?}"
    );
}

/// Cross-checks that an SSHSIG produced by `gitway-keygen` is accepted by
/// OpenSSH's `ssh-keygen -Y check-novalidate`.
#[test]
#[ignore = "requires OpenSSH `ssh-keygen` on PATH"]
fn openssh_can_verify_our_signature() {
    let Some(openssh) = find_ssh_keygen() else {
        eprintln!("skipping: no ssh-keygen on PATH");
        return;
    };
    let dir = TempDir::new().unwrap();
    let key_path = generate_test_key(&dir);
    let payload = b"cross-compat payload";

    // Sign with gitway-keygen.
    let mut child = Command::new(gitway_keygen())
        .args(["-Y", "sign", "-n", "git", "-f", key_path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let sign_output = child.wait_with_output().unwrap();
    assert!(sign_output.status.success());
    let sig_path = dir.path().join("sig");
    fs::write(&sig_path, sign_output.stdout).unwrap();

    // Verify with OpenSSH's ssh-keygen.
    let mut child = Command::new(&openssh)
        .args([
            "-Y",
            "check-novalidate",
            "-n",
            "git",
            "-s",
            sig_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn ssh-keygen");
    child.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let verify_output = child.wait_with_output().unwrap();
    assert!(
        verify_output.status.success(),
        "OpenSSH rejected our signature: stderr={:?}",
        String::from_utf8_lossy(&verify_output.stderr),
    );
}
