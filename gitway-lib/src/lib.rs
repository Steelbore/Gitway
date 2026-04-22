// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-05
// S3: enforce zero unsafe in all project-owned code at compile time.
#![forbid(unsafe_code)]
//! # gitway-lib
//!
//! Purpose-built SSH transport library for Git operations against GitHub,
//! GitLab, Codeberg, and self-hosted Git instances.
//!
//! Written in pure Rust on top of [`russh`](https://docs.rs/russh) v0.59, it
//! replaces the general-purpose `ssh` binary in the Git transport pipeline.
//!
//! ## Quick start
//!
//! ```no_run
//! use gitway_lib::{GitwayConfig, GitwaySession};
//!
//! # async fn doc() -> Result<(), gitway_lib::GitwayError> {
//! // GitHub
//! let config = GitwayConfig::github();
//! // GitLab
//! let config = GitwayConfig::gitlab();
//! // Codeberg
//! let config = GitwayConfig::codeberg();
//!
//! let mut session = GitwaySession::connect(&config).await?;
//! session.authenticate_best(&config).await?;
//!
//! let exit_code = session.exec("git-upload-pack 'user/repo.git'").await?;
//! session.close().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Design principles
//!
//! - **Pinned host keys** — SHA-256 fingerprints for GitHub, GitLab, and
//!   Codeberg are embedded; no TOFU (Trust On First Use) for known hosts.
//! - **Narrow scope** — only exec channels; no PTY, SFTP, or port forwarding.
//! - **Post-quantum ready** — uses `aws-lc-rs` for cryptography.
//! - **Metric / SI / ISO 8601** throughout all timestamps and measurements.

pub mod agent;
pub mod allowed_signers;
pub mod auth;
pub mod config;
pub mod diagnostic;
pub mod error;
pub mod hostkey;
pub mod keygen;
pub mod relay;
pub mod session;
pub mod sshsig;
pub mod time;

// ── Flat re-exports (FR-23) ───────────────────────────────────────────────────

pub use config::GitwayConfig;
pub use error::GitwayError;
pub use session::GitwaySession;
