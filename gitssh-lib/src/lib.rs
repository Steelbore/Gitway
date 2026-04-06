// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-05
// S3: enforce zero unsafe in all project-owned code at compile time.
#![forbid(unsafe_code)]
//! # gitssh-lib
//!
//! Purpose-built SSH transport library for Git operations against GitHub and
//! GitHub Enterprise Server (GHE).
//!
//! Written in pure Rust on top of [`russh`](https://docs.rs/russh) v0.59, it
//! replaces the general-purpose `ssh` binary in the Git transport pipeline.
//!
//! ## Quick start
//!
//! ```no_run
//! use gitssh_lib::{GitsshConfig, GitsshSession};
//!
//! # async fn doc() -> Result<(), gitssh_lib::GitsshError> {
//! let config = GitsshConfig::github();
//! let mut session = GitsshSession::connect(&config).await?;
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
//! - **Pinned host keys** — GitHub's SHA-256 fingerprints are embedded; no
//!   TOFU (Trust On First Use) for canonical GitHub hosts.
//! - **Narrow scope** — only exec channels; no PTY, SFTP, or port forwarding.
//! - **No C runtime** — uses `ring` exclusively for cryptography.
//! - **Metric / SI / ISO 8601** throughout all timestamps and measurements.

pub mod auth;
pub mod config;
pub mod error;
pub mod hostkey;
pub mod relay;
pub mod session;

// ── Flat re-exports (FR-23) ───────────────────────────────────────────────────

pub use config::GitsshConfig;
pub use error::GitsshError;
pub use session::GitsshSession;
