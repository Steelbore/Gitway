// SPDX-License-Identifier: GPL-3.0-or-later
//! # gitway-lib — DEPRECATED
//!
//! `gitway-lib` was renamed and extracted to
//! [`anvil-ssh`](https://crates.io/crates/anvil-ssh).  This crate is a
//! thin compatibility shim that re-exports the entire Anvil API under
//! the legacy `gitway_lib::*` module path for one major version per
//! [Gitway PRD §7.4](https://github.com/steelbore/gitway/blob/main/Gitway-PRD-v1.0.md).
//!
//! Migrate by updating your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! anvil-ssh = "0.1"
//! ```
//!
//! and replacing `use gitway_lib::*;` with `use anvil_ssh::*;` across
//! your source.  The type names (`GitwaySession`, `GitwayConfig`,
//! `GitwayError`) carry forward unchanged through Anvil `0.1.x`, so
//! the migration is mechanical.  They will rename to `Anvil*` with
//! their own `#[deprecated]` aliases in Anvil `0.2.0`.
//!
//! Source repo for the library: <https://github.com/Steelbore/Anvil>.

#![forbid(unsafe_code)]
#![deprecated(
    since = "1.0.0",
    note = "use the `anvil-ssh` crate directly; see https://github.com/Steelbore/Anvil"
)]

pub use anvil_ssh::*;
