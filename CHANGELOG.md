# Changelog

All notable changes to Gitway are documented here.  The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] — 2026-05-05

The first stable release of Gitway: a pure-Rust SSH toolkit for
Git that replaces the OpenSSH binary in the Git transport
pipeline plus the subset of `ssh-keygen`, `ssh-add`, and
`ssh-agent` that day-to-day Git workflows need.

This entry summarizes everything that landed across the v1.0
feature series (M11.5 through M19, all `1.0.0-rc.x` tags) plus
the v1.0-specific stabilization work (M20).

### Highlights

- **Drop-in `core.sshCommand`.**  `gitway --install` registers
  Gitway with Git globally; transport, signing, and agent operations
  work without OpenSSH on the host.
- **Pure-Rust crypto stack.**  No `unsafe` in any project-owned
  crate; aws-lc-rs for transport crypto, ssh-key for SSHSIG and
  keygen.
- **Pinned host keys.**  GitHub, GitLab, and Codeberg fingerprints
  are embedded at build time; man-in-the-middle attempts trip
  `check_server_key` and abort.
- **Full `ssh_config(5)` story.**  `~/.ssh/config` parsed with all
  the directives day-to-day Git workflows need: `Host`, `HostName`,
  `Port`, `User`, `IdentityFile`, `ProxyCommand`, `ProxyJump`,
  `KexAlgorithms`, `Ciphers`, `MACs`, `HostKeyAlgorithms`,
  `ConnectTimeout`, `ConnectionAttempts`, `Include`,
  `UserKnownHostsFile`, `StrictHostKeyChecking`,
  `IdentitiesOnly`, `IdentityAgent`, `CertificateFile`.
  `gitway config show` mirrors `ssh -G`.
- **Bastions and jump hosts.**  `-J bastion.example -- git fetch`
  works; `gitway config show` renders the chain.
- **`-vvv` debug parity with OpenSSH.**  `tracing`-based
  pipeline; `--debug-format=json` emits one JSON record per line
  on stderr.
- **Connection retry and backoff.**  `--connect-timeout`,
  `--attempts`, `--max-retry-window`; transient-vs-fatal
  classifier; per-attempt history surfaced on
  `--test --json`.
- **`known_hosts` hygiene.**  `gitway hosts {add,revoke,list}`
  manages the user's known_hosts file with hashed-entry support
  and a `@revoked` blocklist.
- **Algorithm catalogue.**  `gitway list-algorithms` enumerates
  every algorithm Gitway supports, tagged `default`,
  `available`, or `denylisted`; `--kex` / `--ciphers` / `--macs`
  / `--host-key-algorithms` accept OpenSSH's `+/-/^/replace`
  syntax.
- **Stable JSON envelope contract.**  Every `--json` output
  carries `metadata.schema_version = "1.0.0"`; agents and CI
  parsers can pin against it.  See `docs/json-schema.md`.

### Added (since v0.9)

- **M12 — `~/.ssh/config` parser** (`anvil-ssh = "0.3.0"`,
  `v1.0.0-rc.3`).  Lexer / parser / matcher / resolver / `Include`
  expansion.  `AnvilConfig::apply_ssh_config()` builder method.
  `gitway config show <host>` subcommand.  Global `--no-config`
  flag.  `Match` blocks parsed but never matched (deferred to
  v1.1; see `docs/ssh_config-deviations.md`).
- **M13 — `ProxyCommand` + `ProxyJump`** (`anvil-ssh = "0.4.0"`,
  `v1.0.0-rc.4`).  Token expansion (`%h %p %r %n %%`),
  `JumpHost` / `parse_jump_chain` (8-hop cap per FR-57),
  independent host-key verification at every hop (NFR-17),
  `ProxyCommand=none` disable sentinel (FR-59).  Gitway flags
  `--proxy-command` and `-J` / `--jump-host` (repeatable).
  `gitway config show` per-hop chain visualization.
- **M14 (partial) — `@cert-authority` host CA**
  (`anvil-ssh = "0.5.0"`, `v1.0.0-rc.5`).  `parse_known_hosts`,
  `cert_authority::CertAuthority`, `host_key_trust` API.
  `@revoked` enforcement in `check_server_key` as a
  policy-overriding blocklist (FR-64).  `cert_authorities` and
  `revoked` audit-log keys in `gitway config show --json` and
  `gitway --test --json`.  **FR-61, FR-62, FR-63 (live cert
  validation during KEX) deferred to v1.1** — blocked on russh
  upstream cert-host-key support.  See `docs/ssh_config-deviations.md`.
- **M15 — `-vv`, `-vvv`, JSONL debug** (`anvil-ssh = "0.6.0"`,
  `v1.0.0-rc.6`).  `tracing`-based pipeline; `anvil_ssh::log`
  module with per-category target constants (`CAT_KEX`,
  `CAT_AUTH`, `CAT_CHANNEL`, `CAT_CONFIG`, `CAT_RETRY`).
  Gitway flags `-v`/`-vv`/`-vvv`, `--debug-format=<human|json>`
  (FR-68), `--debug-categories=<list>` (FR-69).  `RUST_LOG`
  override per SFRS §3.
- **M19 — `known_hosts` hygiene** (`anvil-ssh = "0.7.0"`,
  `v1.0.0-rc.7`).  `HashKnownHosts yes` privacy format support
  (HMAC-SHA1, `|1|salt|hash`).  `append_known_host_hashed`,
  `prepend_revoked` (atomic tempfile+rename, 1 MiB cap),
  `all_embedded`, `HashMode` / `detect_hash_mode`.
  `gitway hosts add` / `revoke` / `list` subcommand family
  (FR-85, FR-86, FR-87).
- **M17 — Algorithm overrides** (`anvil-ssh = "0.8.0"`,
  `v1.0.0-rc.8`).  `algorithms::DENYLIST` (DSA, 3DES, RC4,
  hmac-sha1-96, ssh-1.0); `apply_overrides` (`+`/`-`/`^`/replace
  syntax, FR-77); `Catalogue` + `all_supported()` (FR-79).
  Gitway flags `--kex`, `--ciphers`, `--macs`,
  `--host-key-algorithms`.  New subcommand `gitway list-algorithms`.
  `apply_ssh_config` honors the four `ssh_config` directives.
- **M18 — Connection retry, backoff, and timeouts**
  (`anvil-ssh = "0.9.0"`, `v1.0.0-rc.9`).  `retry::RetryPolicy`,
  `RetryAttempt`, `Disposition`, `classify` (FR-82); generic
  `retry::run` exponential-backoff-with-jitter executor;
  per-attempt `tokio::time::timeout`.  `AnvilConfig` fields
  `connect_timeout` / `connection_attempts` / `max_retry_window`
  with builder setters.  `apply_ssh_config` now fully consumes
  every supported directive.  Gitway flags `--connect-timeout`,
  `--attempts`, `--max-retry-window`.  `--test --json` envelope
  gains `retry_attempts: [{attempt, reason, elapsed_ms}]`
  (FR-83).
- **M20.2 — JSON envelope contract**
  (`schema_version = "1.0.0"`).  Every `--json` and always-JSON
  surface now carries `metadata.schema_version`.  `gitway schema`
  / `gitway describe` updated with M15/M17/M18/M19 surfaces and
  flags.  `gitway-cli/tests/agent_env.rs` snapshot test.
- **M20.2 — Agent env-var detection.**  Auto-JSON-mode now also
  fires on `CLAUDECODE=1`, `CURSOR_AGENT=1`, `GEMINI_CLI=1`
  (in addition to the existing `AI_AGENT=1`, `AGENT=1`,
  `CI=true`).
- **Documentation deliverables for v1.0:**
  - `docs/json-schema.md` — JSON envelope contract + bump policy
  - `docs/exit-codes.md` — full exit-code table (0/1/2/3/4 + 73/78)
  - `docs/log-format.md` — log surface stability tier
  - `docs/error-hints.md` — `error.code` stable; message/hint advisory
  - `docs/ssh_config-deviations.md` — every place we diverge from OpenSSH
  - `docs/migration-from-v0.9.md` — end-user + library migration
  - `docs/security.md` — threat model
  - `docs/v1.0.0-readiness.md` — S1-S5/S7 success-metric audit
  - `SECURITY.md` (repo root) — disclosure policy

### Changed

- **Workspace version** bumped to `1.0.0` (was `0.9.0`).
- **`anvil-ssh` dependency** bumped to `1.0.0`.
- **JSON envelope shape:** all `--json` surfaces add
  `metadata.schema_version = "1.0.0"`.  Existing fields are
  unchanged in shape and type.
- **Error envelope shape:** moved `timestamp` and `command` from
  the `error` object into the new `metadata` block (the `error`
  object now carries only `code`, `exit_code`, `message`,
  `hint`).  Tools that read the JSON-mode error envelope should
  look for those fields under `metadata.timestamp` and
  `metadata.command` instead of `error.timestamp` /
  `error.command`.
- **`run_describe` output** adds an `agent_env_vars` array
  enumerating every env var that triggers auto-JSON-mode.

### Deprecated

- **`gitway-lib` crate.**  The compat shim is preserved in v1.x
  but marked `#[deprecated]`.  Direct library users should
  switch to `anvil-ssh` 1.0.  Removal is planned for v2.0.
  See `docs/migration-from-v0.9.md`.

### Removed

Nothing.  v1.0 is a stabilization release; no public API was
removed since v0.9.

### Out of scope for v1.0

These are explicit deferrals, not bugs:

- **M16 — FIDO2 / `sk-ssh-*` hardware keys.**  Vendor
  fragmentation across YubiKey 5, SoloKeys, OnlyKey requires a
  hardware-test matrix that is post-1.0 work.  Tracked at PRD
  §13.
- **M14 FR-61/62/63 — live `@cert-authority` validation during
  KEX.**  Blocked on russh upstream cert-host-key support;
  tracked upstream.
- **§12 Q1 — full `Match` block semantics.**  `Match` blocks
  parsed but never match in v1.0.
- **HTTP 429/503 retry semantics.**  No HTTP layer in the
  transport path; out of scope by construction.

If your workflow depends on any of the above, **stay on OpenSSH
for those specific operations** until the referenced minor
release.

### Security

- **`#![forbid(unsafe_code)]`** preserved in every project-owned
  crate (`gitway-cli`, `gitway-lib`, `anvil-ssh`).
- **Pinned host-key fingerprints** for github.com, gitlab.com,
  codeberg.org embedded at build time.
- **Algorithm denylist** unconditionally refuses DSA, 3DES,
  Arcfour, hmac-sha1-96, and ssh-1.0 — no flag can re-enable.
- **`@revoked`** enforcement runs **before** any
  `StrictHostKeyChecking=no` bypass; revocations cannot be
  overridden.
- **Passphrase zeroization** via `Zeroizing<String>` everywhere
  passphrases live in memory.
- **`SSH_ASKPASS` validation:** absolute-path required;
  world-writable askpass programs rejected on Unix.

See `docs/security.md` for the full threat model and
`SECURITY.md` for the disclosure policy.

## [0.9.0] — 2026-05-05 (`v1.0.0-rc.9`)

M18 — connection retry, backoff, and timeouts (FR-80..FR-83).
See PRD §8 for the milestone summary; this CHANGELOG entry
records only release-engineering metadata for the rc.

## [0.8.0] — 2026-05-04 (`v1.0.0-rc.8`)

M17 — algorithm overrides (FR-76..FR-79).

## [0.7.0] — 2026-05-04 (`v1.0.0-rc.7`)

M19 — known_hosts hygiene (FR-84..FR-87).

## [0.6.0] — 2026-05-04 (`v1.0.0-rc.6`)

M15 — `-vv`, `-vvv`, JSONL debug (FR-65..FR-69).

## [0.5.0] — 2026-05-04 (`v1.0.0-rc.5`)

M14 (partial) — `@cert-authority` host CA (FR-60, FR-64).

## [0.4.0] — 2026-05-04 (`v1.0.0-rc.4`)

M13 — `ProxyCommand` and `ProxyJump` (FR-55..FR-59).

## [0.3.0] / 0.3.1 — 2026-05-04 (`v1.0.0-rc.3`)

M12 — `~/.ssh/config` parser (FR-40..FR-54).

## [0.2.0] — 2026-05-04 (`v1.0.0-rc.2`)

M11.5 — `Gitway*` to `Anvil*` type rename with `#[deprecated]`
aliases.

## [0.1.0] — 2026-05-03 (`v1.0.0-rc.1`)

M11.5 — Anvil extraction (cold-start), no behavior change.

## Older releases (v0.1 through v0.9 line)

See `docs/PRD.md` and the git history for milestone-by-milestone
detail of M1 through M11.5.
