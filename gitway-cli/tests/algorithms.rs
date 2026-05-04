// SPDX-License-Identifier: GPL-3.0-or-later
//! Subprocess integration tests for `gitway list-algorithms` (FR-79)
//! and the algorithm-override flags `--kex` / `--ciphers` / `--macs` /
//! `--host-key-algorithms` (FR-77, FR-78).
//!
//! Drives the compiled `gitway` binary; assertions land on stdout
//! (JSON envelope) and exit code only.  No network, no russh server
//! — the `--kex` denylist test reaches the `apply_overrides`
//! validation path before any connection attempt.

use std::path::PathBuf;
use std::process::Command;

fn gitway() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gitway"))
}

// ── list-algorithms (FR-79) ─────────────────────────────────────────────────

#[test]
fn list_algorithms_json_emits_envelope_with_four_categories() {
    let output = Command::new(gitway())
        .arg("list-algorithms")
        .env("AI_AGENT", "1")
        .output()
        .expect("spawn gitway");
    assert!(
        output.status.success(),
        "gitway list-algorithms exited {} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let envelope: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("parse JSON envelope");

    // metadata block.
    assert_eq!(envelope["metadata"]["tool"], "gitway");
    assert_eq!(envelope["metadata"]["command"], "gitway list-algorithms");
    assert!(envelope["metadata"]["timestamp"].is_string());
    assert!(envelope["metadata"]["version"].is_string());

    // data block — four categories, each non-empty.
    let kex = envelope["data"]["kex"].as_array().expect("kex array");
    let cipher = envelope["data"]["cipher"].as_array().expect("cipher array");
    let mac = envelope["data"]["mac"].as_array().expect("mac array");
    let host_key = envelope["data"]["host_key"]
        .as_array()
        .expect("host_key array");
    assert!(!kex.is_empty());
    assert!(!cipher.is_empty());
    assert!(!mac.is_empty());
    assert!(!host_key.is_empty());

    // Every entry has the documented shape.
    for entry in kex.iter().chain(cipher).chain(mac).chain(host_key) {
        assert!(entry["name"].is_string());
        assert!(entry["is_default"].is_boolean());
        assert!(entry["denylisted"].is_boolean());
    }

    // At least one default per category.
    for category in [kex, cipher, mac, host_key] {
        assert!(
            category.iter().any(|e| e["is_default"] == true),
            "category missing a default entry: {category:?}",
        );
    }
}

#[test]
fn list_algorithms_json_marks_denylisted_entries() {
    let output = Command::new(gitway())
        .arg("list-algorithms")
        .env("AI_AGENT", "1")
        .output()
        .expect("spawn gitway");
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).expect("parse JSON");

    // 3des-cbc must appear in the cipher category tagged denylisted.
    let cipher = envelope["data"]["cipher"].as_array().expect("cipher");
    let three_des = cipher
        .iter()
        .find(|e| e["name"] == "3des-cbc")
        .expect("3des-cbc must appear in the cipher catalogue");
    assert_eq!(three_des["denylisted"], true);
    assert_eq!(three_des["is_default"], false);

    // ssh-dss must appear in the host-key category tagged denylisted.
    let host_key = envelope["data"]["host_key"].as_array().expect("host_key");
    let dsa = host_key
        .iter()
        .find(|e| e["name"] == "ssh-dss")
        .expect("ssh-dss must appear in the host-key catalogue");
    assert_eq!(dsa["denylisted"], true);
    assert_eq!(dsa["is_default"], false);
}

// ── algorithm overrides (FR-77, FR-78) ──────────────────────────────────────

#[test]
fn kex_override_with_denylisted_alg_exits_nonzero() {
    // `--kex +ssh-1.0` references a denylisted algorithm.
    // apply_overrides should refuse before any connection is attempted.
    let output = Command::new(gitway())
        .arg("--kex")
        .arg("+ssh-1.0")
        .arg("--test")
        .arg("--host")
        .arg("nonexistent-host-for-m17-test.invalid")
        .env("AI_AGENT", "1")
        .output()
        .expect("spawn gitway");

    assert!(
        !output.status.success(),
        "gitway --kex +ssh-1.0 must fail before connect; got exit 0",
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("ssh-1.0") || stderr.contains("denylisted") || stderr.contains("FR-78"),
        "stderr must mention the denylisted alg or FR-78; got: {stderr}",
    );
}

#[test]
fn ciphers_override_with_3des_exits_nonzero() {
    // Same shape as the kex test, different category.
    let output = Command::new(gitway())
        .arg("--ciphers")
        .arg("+3des-cbc")
        .arg("--test")
        .arg("--host")
        .arg("nonexistent-host-for-m17-test.invalid")
        .env("AI_AGENT", "1")
        .output()
        .expect("spawn gitway");
    assert!(
        !output.status.success(),
        "gitway --ciphers +3des-cbc must fail before connect",
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("3des-cbc") || stderr.contains("denylisted") || stderr.contains("FR-78"),
    );
}

#[test]
fn host_key_algorithms_override_with_dsa_exits_nonzero() {
    let output = Command::new(gitway())
        .arg("--host-key-algorithms")
        .arg("+ssh-dss")
        .arg("--test")
        .arg("--host")
        .arg("nonexistent-host-for-m17-test.invalid")
        .env("AI_AGENT", "1")
        .output()
        .expect("spawn gitway");
    assert!(
        !output.status.success(),
        "gitway --host-key-algorithms +ssh-dss must fail before connect",
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("ssh-dss") || stderr.contains("denylisted") || stderr.contains("FR-78"),
    );
}
