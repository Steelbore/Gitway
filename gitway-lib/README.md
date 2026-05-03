# gitway-lib — DEPRECATED

> **This crate has been superseded by [`anvil-ssh`](https://crates.io/crates/anvil-ssh).**

The pure-Rust SSH stack that powered Gitway has been extracted into a standalone Steelbore library at [Steelbore/Anvil](https://github.com/Steelbore/Anvil).

## Migrate

Update your `Cargo.toml`:

```toml
[dependencies]
anvil-ssh = "0.1"
```

and replace `use gitway_lib::*;` with `use anvil_ssh::*;` across your source.

The type names (`GitwaySession`, `GitwayConfig`, `GitwayError`) carry forward unchanged through Anvil `0.1.x`, so the migration is mechanical.  They will rename to `Anvil*` with their own `#[deprecated]` aliases in Anvil `0.2.0`.

## Background

See [Gitway PRD §7.4](https://github.com/steelbore/gitway/blob/main/Gitway-PRD-v1.0.md) for the full extraction plan.

`gitway-lib 0.9.x` is the final published release under the `gitway-lib` name.  The in-tree `gitway-lib/` directory in the Gitway workspace is now a thin compat shim that re-exports `anvil_ssh::*`; it is not republished to crates.io.
