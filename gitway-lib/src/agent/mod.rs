// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-21
//! SSH-agent wire-protocol support.
//!
//! Phase 2 of §5.7 ships the *client* side: talk to any running agent
//! (Gitway's future daemon or OpenSSH's `ssh-agent`) over `$SSH_AUTH_SOCK`.
//! Phase 3 will add the daemon side in `agent::daemon`.
//!
//! Unix-only for Phase 2 — Windows named-pipe transport is deferred to the
//! daemon work.

pub mod askpass;
pub mod client;
pub mod daemon;
