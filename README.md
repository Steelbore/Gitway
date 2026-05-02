# Gitway

Purpose-built SSH transport client for Git operations against GitHub and GitHub
Enterprise Server (GHE).

[![CI](https://github.com/steelbore/gitway/actions/workflows/ci.yml/badge.svg)](https://github.com/steelbore/gitway/actions/workflows/ci.yml)
[![Crates.io: gitway](https://img.shields.io/crates/v/gitway.svg)](https://crates.io/crates/gitway)
[![Crates.io: gitway-lib](https://img.shields.io/crates/v/gitway-lib.svg)](https://crates.io/crates/gitway-lib)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![MSRV: 1.85](https://img.shields.io/badge/rustc-1.85%2B-orange.svg)](rust-toolchain.toml)

---

## Why Gitway?

General-purpose SSH clients (`ssh`, PuTTY) carry complexity that Git doesn't
need — interactive shells, tunneling, agent forwarding, hundreds of config
directives. That complexity causes three concrete pain points:

- **Configuration errors** — a misconfigured `~/.ssh/config` silently routes
  traffic through the wrong key.
- **Fragile host-key trust** — the first-connection TOFU model forces developers
  to blindly accept a fingerprint.
- **Windows inconsistency** — multiple competing SSH implementations with
  incompatible agent protocols.

Gitway solves these by being opinionated: it connects only to GitHub, pins
GitHub's published host-key fingerprints, searches for keys in a predictable
order, and behaves identically on Linux, macOS, and Windows.

---

## Features

- **Pinned host keys** — GitHub's SHA-256 Ed25519, ECDSA, and RSA fingerprints
  are embedded in the binary. No TOFU. A key mismatch aborts immediately.
- **Automatic key discovery** — searches `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`,
  `~/.ssh/id_rsa` in order, then falls back to the SSH agent.
- **Passphrase support** — prompts securely via `rpassword`; passphrase memory is
  zeroized on drop.
- **OpenSSH certificates** — pass a certificate alongside your key with `--cert`.
- **GitHub Enterprise Server** — add GHE fingerprints to
  `~/.config/gitway/known_hosts`.
- **Drop-in replacement** — works with `GIT_SSH_COMMAND` and `core.sshCommand`
  exactly as `ssh` does.
- **Library crate** — embed `gitway-lib` directly in Rust projects for
  programmatic Git transport.
- **Single static binary** — no C runtime, no OpenSSL, no system SSH required.

---

## Installation

### From source

**Nushell:**
```nu
cargo install --path gitway-cli
```

**Ion:**
```ion
cargo install --path gitway-cli
```

**Bash/Brush:**
```bash
cargo install --path gitway-cli
```

### On Alpine Linux

No Alpine package exists yet. The pre-built static musl binary from the GitHub
Releases page runs natively on Alpine with no libc dependency.

**Option A — pre-built binary (recommended):**
```sh
# Download and install the latest release binary
wget -qO- https://github.com/steelbore/gitway/releases/latest/download/gitway-linux-x86_64.tar.gz \
  | tar -xz
sudo install -m755 gitway          /usr/local/bin/gitway
sudo install -m755 gitway-keygen   /usr/local/bin/gitway-keygen
sudo install -m755 gitway-add      /usr/local/bin/gitway-add
```

**Option B — build from source:**
```sh
apk add cargo gcc perl pkgconf
cargo install gitway gitway-keygen
```

### On Arch Linux

Two AUR packages are provided. `gitway-bin` installs the pre-built musl binary
and is recommended for most users — no compiler required.

**With an AUR helper (yay):**
```sh
yay -S gitway-bin
```

**With an AUR helper (paru):**
```sh
paru -S gitway-bin
```

**Without an AUR helper (manual):**
```sh
git clone https://aur.archlinux.org/gitway-bin.git
cd gitway-bin
makepkg -si
```

To track git HEAD instead (builds from source), use `gitway-git` in place of
`gitway-bin`. The PKGBUILDs for both packages are also shipped in
[`packaging/arch/`](packaging/arch/) in this repository.

### On Debian / Ubuntu

Pre-built `.deb` packages are produced by the CI release workflow and attached
to every GitHub release.

**Install a pre-built package:**
```sh
# Download the .deb for your architecture from the Releases page, then:
sudo apt install ./gitway_*.deb
```

**Build locally:**
```sh
sudo apt install cargo gcc perl pkg-config
cargo install cargo-deb
cargo deb -p gitway
sudo apt install ./target/debian/gitway_*.deb
```

On older Debian or Ubuntu releases the packaged Rust toolchain may be too old.
Install a current toolchain via [rustup](https://rustup.rs) and retry.

### On Fedora

Pre-built `.rpm` packages are produced by the CI release workflow and attached
to every GitHub release.

**Install a pre-built package:**
```sh
# Download the .rpm from the Releases page, then:
sudo dnf install ./gitway-*.rpm
```

**Build locally:**
```sh
sudo dnf install cargo gcc perl pkgconf-pkg-config
cargo install cargo-generate-rpm
cargo build --release -p gitway
cargo generate-rpm -p gitway-cli
sudo dnf install ./target/generate-rpm/gitway-*.rpm
```

### On Gentoo

No ebuild is in the main Gentoo tree yet. The pre-built static musl binary
works on both glibc and musl Gentoo profiles.

**Pre-built binary:**
```sh
# Download and install from the Releases page, then:
sudo install -m755 gitway          /usr/local/bin/gitway
sudo install -m755 gitway-keygen   /usr/local/bin/gitway-keygen
sudo install -m755 gitway-add      /usr/local/bin/gitway-add
```

**Build from source:**
```sh
emerge dev-lang/rust
cargo install gitway gitway-keygen
```

### On openSUSE

Pre-built `.rpm` packages are produced by the CI release workflow and attached
to every GitHub release.

**Install a pre-built package:**
```sh
# Download the .rpm from the Releases page, then:
sudo zypper install ./gitway-*.rpm
```

**Build locally:**
```sh
sudo zypper install cargo gcc perl pkg-config
cargo install cargo-generate-rpm
cargo build --release -p gitway
cargo generate-rpm -p gitway-cli
sudo zypper install ./target/generate-rpm/gitway-*.rpm
```

### On Windows

Pre-built Windows binaries are attached to every GitHub release as a `.zip`
archive.

**Install a pre-built binary (recommended):**

1. Download `gitway-windows-x86_64.zip` from the
   [Releases page](https://github.com/steelbore/gitway/releases/latest).
2. Extract the archive and place `gitway.exe`, `gitway-keygen.exe`, and
   `gitway-add.exe` in a directory of your choice (e.g. `C:\tools\gitway\`).
3. Add that directory to your **System** `PATH` via
   *System Properties → Environment Variables → System variables → Path → Edit*.
   Using the System PATH (not the User PATH) ensures IDEs and non-interactive
   processes launched by Windows can find `gitway`.
4. Open a new terminal and verify: `gitway --test`

**Build from source:**

`aws-lc-rs` requires [NASM](https://www.nasm.us/) during compilation.
Install it before running `cargo install`:

```powershell
winget install nasm
# or: choco install nasm
# then restart the terminal so nasm.exe is on PATH
cargo install gitway gitway-keygen
```

**Agent on Windows:**

The Gitway agent uses the Windows named-pipe transport
(`\\.\pipe\gitway-agent.<PID>` by default), compatible with
OpenSSH for Windows's `\\.\pipe\openssh-ssh-agent`.

Background daemon mode (auto-detach) is Unix-only. To keep the agent running
on Windows, start it in a separate terminal with `-D` and leave it open:

```powershell
gitway agent start -D
```

To stop it, press `Ctrl+C` in that terminal, or use `Stop-Process` / Task Manager.
For an always-on agent, wrap `gitway agent start -D` in a Windows service using
a tool such as NSSM or a scheduled task with *Run whether user is logged on or not*.

### On NixOS

Gitway exposes a flake at `github:steelbore/gitway`. Three install paths
are supported, in order of increasing declarativeness.

**Imperative, per-user — `nix profile`:**
```sh
nix profile install github:steelbore/gitway
```

Installs `gitway`, `gitway-keygen`, and `gitway-add` into
`~/.nix-profile/bin/`. Upgrade later with
`nix profile upgrade gitway`.

**One-shot run without installing:**
```sh
nix run github:steelbore/gitway -- --test
```

**Declarative, system-wide — flake input on NixOS:**

In `/etc/nixos/flake.nix`:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    gitway.url  = "github:steelbore/gitway";
  };

  outputs = { self, nixpkgs, gitway, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system  = "x86_64-linux";
      modules = [
        ({ pkgs, ... }: {
          environment.systemPackages = [
            gitway.packages.${pkgs.system}.default
          ];
        })
      ];
    };
  };
}
```

Then `sudo nixos-rebuild switch`.

**Declarative, per-user — flake input via home-manager:**

With `gitway` passed into the home-manager config as a flake input:

```nix
{ gitway, pkgs, ... }: {
  home.packages = [ gitway.packages.${pkgs.system}.default ];
}
```

### Register as the global Git SSH command

**All shells:**
```sh
gitway --install
# Runs: git config --global core.sshCommand gitway
```

The `--install` command writes one line into your `~/.gitconfig`:

```ini
[core]
    sshCommand = gitway
```

Verify it:
```sh
git config --global --get core.sshCommand
# → gitway
```

Remove it to fall back to OpenSSH:
```sh
git config --global --unset core.sshCommand
```

After this, every `git clone`, `git fetch`, and `git push` over SSH uses Gitway
automatically. Make sure `gitway` itself is on a PATH that *non-interactive*
shells see — see **[Making gitway discoverable to Git](#making-gitway-discoverable-to-git)**
below.

---

## Making gitway discoverable to Git

Git invokes `core.sshCommand = gitway` via `execvp`, which walks the
**current process's** `PATH` — not the PATH you see in your terminal.
IDEs, GUI git clients, systemd user services, and most launchers start
processes *without* sourcing `~/.bashrc` / `~/.zshrc` / `~/.ionrc`, so
paths added only in an interactive-shell rc file are invisible to them.

The gitway binary must live somewhere every inherited environment sees:

**NixOS** — all three standard Nix profile paths are injected into PATH by
the NixOS PAM stack and thus visible to non-interactive shells and GUI
apps:

- `~/.nix-profile/bin/gitway` — from `nix profile install github:steelbore/gitway`
- `/etc/profiles/per-user/$USER/bin/gitway` — from home-manager
  `home.packages` (including `services.gitway-agent.enable = true`)
- `/run/current-system/sw/bin/gitway` — from NixOS
  `environment.systemPackages`

**Debian / RPM distros** — `/usr/bin/gitway` from the official `.deb` or
`.rpm` package is universal. Every shell, every launcher, every systemd
unit can reach it without configuration.

**`cargo install` users (`~/.cargo/bin`)** — this is the classic footgun.
`~/.cargo/bin` is on PATH **only** if it's exported system-wide (in
`/etc/environment`, `~/.profile`, `~/.pam_environment`, or a systemd
`environment.d` drop-in), **not** if it's only added in `.bashrc`. If
`git push` works from your terminal but fails from your IDE with a bare
`exit 128`, this is almost certainly why.

Two fixes:

```sh
# Option 1 — install gitway into a system-wide location:
sudo install -m755 ~/.cargo/bin/gitway        /usr/local/bin/gitway
sudo install -m755 ~/.cargo/bin/gitway-keygen /usr/local/bin/gitway-keygen
sudo install -m755 ~/.cargo/bin/gitway-add    /usr/local/bin/gitway-add

# Option 2 — add ~/.cargo/bin to a PATH file that non-interactive shells
# read.  On most Linux distros, /etc/environment is the right spot:
echo 'PATH="/home/'$USER'/.cargo/bin:/usr/bin:/bin"' | sudo tee -a /etc/environment
# (and log out + back in)
```

Quick diagnostic — does a stripped environment see `gitway`?

```sh
env -i PATH=/usr/bin:/bin which gitway
```

If that prints nothing, neither will your IDE's embedded git.

---

## First-run setup

This puts transport, signing, and agent into a single working configuration.
Three pieces, in order: **agent**, **git config**, **GitHub signing-key
upload**.

### 1. Run the agent and load a key

The agent persists unlocked key material for the session, so Git and `gh`
stop prompting for a passphrase on every push.

#### Option A — Home-Manager (NixOS or Linux with HM)

Enable the module this flake exposes. Add to your `home.nix` (assuming the
flake is imported as a `gitway` input):

```nix
{ gitway, pkgs, ... }: {
  imports = [ gitway.homeManagerModules.default ];

  services.gitway-agent.enable = true;
}
```

Rebuild with `home-manager switch`. The module:

- Installs `gitway`, `gitway-keygen`, and `gitway-add` into your user profile.
- Runs the hardened `gitway agent start -D` as a user systemd service.
- Exports `SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/gitway-agent.sock` into every
  child shell via `home.sessionVariables`.

Load your key once per boot:

```sh
gitway-add ~/.ssh/id_ed25519
```

The agent survives reconnects and shell restarts until you reboot or run
`systemctl --user stop gitway-agent`.

#### Option B — NixOS module (system-wide)

Identical option set, system-scoped:

```nix
{ gitway, ... }: {
  imports = [ gitway.nixosModules.default ];
  services.gitway-agent.enable = true;
}
```

#### Option C — Raw systemd user unit (any distro)

See [`packaging/systemd/gitway-agent.service`](packaging/systemd/gitway-agent.service):

```sh
mkdir -p ~/.config/systemd/user
cp packaging/systemd/gitway-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now gitway-agent.service
```

Then export the socket path in your shell rc (snippet per shell below).

#### Option D — Per-shell, no systemd

Start the agent inside the login shell and export its environment. Fine
for quick smoke tests; Option A/B/C is better for daily use.

**Bash / Brush** — add to `~/.bashrc`:
```bash
if [ -z "$SSH_AUTH_SOCK" ] || ! gitway-add -l >/dev/null 2>&1; then
  eval "$(gitway agent start -s)"
fi
```

**Nushell** — add to `$nu.env-path`:
```nu
if ($env.SSH_AUTH_SOCK? | is-empty) {
    let agent = (^gitway agent start -s)
    $env.SSH_AUTH_SOCK = ($agent | parse -r 'SSH_AUTH_SOCK=([^;]+)' | get capture0.0)
    $env.SSH_AGENT_PID = ($agent | parse -r 'SSH_AGENT_PID=([^;]+)' | get capture0.0)
}
```

**Ion** — Ion has no `eval`. Use Option A/B/C and set `SSH_AUTH_SOCK`
directly in `~/.config/ion/initrc`:
```ion
export SSH_AUTH_SOCK = "${XDG_RUNTIME_DIR}/gitway-agent.sock"
```

### 2. Export `SSH_AUTH_SOCK` if you used Option C

Home-Manager (Option A) and the NixOS module (Option B) do this for you.
For Option C, add one line to your shell rc so every client finds the
running agent:

**Bash / Brush** (`~/.bashrc` / `~/.brushrc`):
```bash
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/gitway-agent.sock"
```

**Nushell** (`$nu.env-path`):
```nu
$env.SSH_AUTH_SOCK = $"($env.XDG_RUNTIME_DIR)/gitway-agent.sock"
```

**Ion** (`~/.config/ion/initrc`):
```ion
export SSH_AUTH_SOCK = "${XDG_RUNTIME_DIR}/gitway-agent.sock"
```

### 3. Configure git for SSH-signed commits

Wire Git to sign every commit with your SSH key via `gitway-keygen` (no
GPG or OpenSSH required). **All shells:**

```sh
# Your identity — use your `noreply` address to hide your real email.
git config --global user.name  "Your Name"
git config --global user.email "youremail@users.noreply.github.com"

# Use the public key as the signing identity.
git config --global user.signingkey ~/.ssh/id_ed25519.pub

# Sign every commit with SSH (not GPG).
git config --global gpg.format     ssh
git config --global gpg.ssh.program gitway-keygen
git config --global commit.gpgsign true
```

`gpg.ssh.program=gitway-keygen` is the wire: Git invokes it exactly the
way it invokes `ssh-keygen -Y sign`, and the shim is byte-compatible with
real ssh-keygen for that argv.

If you haven't already registered gitway as the SSH transport (step 2 of
**Installation** above), also add `core.sshCommand = gitway` — either via
`gitway --install` or by hand in `~/.gitconfig`. Without that line,
`git push` still uses OpenSSH even though commit signing goes through
gitway-keygen.

### 4. Upload the signing key to GitHub

So the Verified badge appears on commits you push. **All shells:**

```sh
# Grant gh the scope it needs to manage signing keys:
gh auth refresh -h github.com -s admin:ssh_signing_key

# Upload the public key:
gh ssh-key add ~/.ssh/id_ed25519.pub --type signing --title "gitway"
```

The `!` prefix in the original recipe (`! gh ssh-key add ...`) is only
relevant inside a Claude Code session — on a normal shell prompt, drop
the `!` and run the command directly.

### 5. Verify end-to-end

```sh
git commit --allow-empty -m "gitway signing smoke test"
git log --show-signature -1      # expect: "Good \"git\" signature ..."
git push
gh api repos/OWNER/REPO/commits/$(git rev-parse HEAD) | jq .commit.verification.verified
# expect: true
```

If verification is `false`, re-check that the **same** key file is
referenced in `user.signingkey` and uploaded to GitHub under
**Settings → SSH and GPG keys → type: Signing Key**.

---

## CLI usage

```
gitway [OPTIONS] <host> <command...>
```

### Options

| Flag | Description |
|---|---|
| `-i, --identity <FILE>` | Path to SSH private key |
| `--cert <FILE>` | OpenSSH certificate alongside the key |
| `-p, --port <PORT>` | SSH port (default: 22) |
| `-v, --verbose` | Enable debug logging to stderr |
| `--insecure-skip-host-check` | **Danger:** skip host-key verification |
| `--test` | Verify connectivity and display the GitHub banner |
| `--install` | Register as `core.sshCommand` in global Git config |

### Examples

**Verify connectivity:**
```sh
gitway --test
```

**Use a specific key:**
```sh
gitway --identity ~/.ssh/id_ed25519_github github.com git-upload-pack 'org/repo.git'
```

**Verbose debug output:**
```sh
gitway --verbose --test
```

**Target a GitHub Enterprise Server instance:**
```sh
gitway --port 22 ghe.corp.example.com git-upload-pack 'org/repo.git'
```

**Use as GIT_SSH_COMMAND for a single operation:**

*Nushell:*
```nu
$env.GIT_SSH_COMMAND = "gitway"
git clone git@github.com:org/repo.git
```

*Ion:*
```ion
export GIT_SSH_COMMAND=gitway
git clone git@github.com:org/repo.git
```

*Bash/Brush:*
```bash
GIT_SSH_COMMAND=gitway git clone git@github.com:org/repo.git
```

---

## GitHub Enterprise Server

Add GHE host-key fingerprints to `~/.config/gitway/known_hosts`. One entry per
line, in the same format as OpenSSH `known_hosts`:

```
ghe.corp.example.com SHA256:<base64-encoded-fingerprint>
```

Retrieve the fingerprint from your GHE instance:

```sh
ssh-keyscan -t ed25519 ghe.corp.example.com | ssh-keygen -lf -
```

---

## Key discovery order

For each connection, Gitway searches for an identity in this fixed priority order:

1. `--identity <FILE>` — explicit path from the command line
2. `~/.ssh/id_ed25519`
3. `~/.ssh/id_ecdsa`
4. `~/.ssh/id_rsa`
5. SSH agent via `$SSH_AUTH_SOCK` (Linux/macOS)

If a key file is encrypted, Gitway prompts for the passphrase on the terminal.

---

## Avoiding repeated passphrase prompts

Gitway is a stateless transport binary: Git launches a fresh `gitway` process
for every SSH transport operation (`clone`, `fetch`, `push`, remote-probing
helpers invoked by tools like `gh`). Each process decrypts the key from
scratch, so an encrypted key without an agent loaded produces one prompt per
invocation — a single `gh repo clone` can easily surface four or five.

Load the key into `ssh-agent` once per session and all subsequent operations
authenticate through the agent without prompting:

```sh
ssh-add ~/.ssh/id_ed25519
```

Gitway detects `$SSH_AUTH_SOCK` and, when an agent is reachable, skips the
file-based passphrase prompt entirely. The same agent also satisfies
`ssh-keygen -Y sign` (Git's default signer for `gpg.format = ssh`), so signed
commits stop prompting as well.

For persistence across reboots, add `ssh-add ~/.ssh/id_ed25519` to your shell
startup file, or use a desktop keyring that unlocks on login (e.g.
`gnome-keyring-daemon --components=ssh`, `gcr-ssh-agent`, or the macOS
Keychain-backed agent).

Caching decrypted keys inside Gitway itself would require a long-lived daemon,
duplicating `ssh-agent` and expanding the attack surface — outside the scope
of a transport client.

---

## Generating keys and signing commits (no OpenSSH required)

Gitway 0.4 ships a subset of `ssh-keygen` so you can generate keys and
SSH-sign git commits without `openssh-clients` installed.

### `gitway keygen` — the Gitway-native UX

```sh
# Generate an Ed25519 keypair:
gitway keygen generate -f ~/.ssh/id_ed25519

# Fingerprint an existing key:
gitway keygen fingerprint -f ~/.ssh/id_ed25519.pub

# Derive the public key from a private key:
gitway keygen extract-public -f ~/.ssh/id_ed25519 -o ~/.ssh/id_ed25519.pub

# Change (or remove) the passphrase:
gitway keygen change-passphrase -f ~/.ssh/id_ed25519
```

All subcommands honor `--json` / `--format json` and the agent-env
detection rules documented under *Dual-mode output* (SFRS Rule 1).

### `gitway sign` — SSHSIG signatures

```sh
# Sign stdin, print the armored SSH SIGNATURE to stdout:
echo 'hello' | gitway sign --namespace git --key ~/.ssh/id_ed25519

# Sign a file:
gitway sign --namespace git --key ~/.ssh/id_ed25519 --input msg.txt --output msg.sig
```

### Verified commits on GitHub — `gpg.ssh.program=gitway-keygen`

Git invokes `gpg.ssh.program` when `gpg.format=ssh`, passing it the exact
ssh-keygen `-Y sign` / `-Y verify` argv. The `gitway-keygen` binary ships
alongside `gitway` specifically to sit in that slot — it is byte-compatible
with `ssh-keygen`'s stdout so git's output parser is satisfied.

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global gpg.ssh.program gitway-keygen
```

Upload the same public key to GitHub under **Settings → SSH and GPG keys →
New SSH key → Key type: Signing Key**. After that, every commit is SSH-signed
via Gitway's code and GitHub shows **Verified** next to it — with zero
OpenSSH involvement.

Everything above uses the pure-Rust `ssh-key` crate (RustCrypto) for the
OpenSSH key format and the SSHSIG file-signature blob.

---

## Loading keys into any SSH agent (no OpenSSH required)

Gitway 0.5 adds a client for the SSH agent wire protocol. It talks to
any agent listening on `$SSH_AUTH_SOCK` — OpenSSH's `ssh-agent`,
Gitway's own future daemon (v0.6), or anything else that speaks the
protocol. Unix-only for now; Windows named-pipe support lands with the
daemon in v0.6.

### `gitway agent` — native UX

```sh
# Load your default key (matches `ssh-add`):
gitway agent add

# Load a specific key with a 10-minute lifetime:
gitway agent add --lifetime 600 ~/.ssh/id_ed25519

# List what's currently loaded:
gitway agent list            # short fingerprints
gitway agent list -L         # full public-key lines

# Remove one or all identities:
gitway agent remove ~/.ssh/id_ed25519.pub
gitway agent remove --all

# Lock / unlock the agent with a passphrase:
gitway agent lock
gitway agent unlock
```

All subcommands honor `--json` / `--format json` and the agent-env
detection rules documented under *Avoiding repeated passphrase prompts*.

### `gitway-add` — ssh-add drop-in

Tools that shell out to `ssh-add` by name (IDEs, git-credential-manager,
systemd user units) can invoke `gitway-add` unchanged. It accepts the
flags most-commonly used: `-l`, `-L`, `-d <file>`, `-D`, `-x`, `-X`,
`-t <seconds>`, `-E <hash>`, `-c`, plus bare positional paths for
`add`.

```sh
eval $(ssh-agent -s)       # or `eval $(gitway agent start -s)` for the Gitway-native daemon
gitway-add ~/.ssh/id_ed25519
gitway-add -l
```

---

## Running a Gitway-native SSH agent (no OpenSSH required)

Gitway 0.6 ships an SSH agent daemon of its own. It speaks the standard
SSH agent wire protocol, so every SSH client — including real OpenSSH —
can use it as a transparent stand-in for `ssh-agent`. Unix-only;
Windows named-pipe transport is a follow-up within the v0.6.x series.

### Starting the daemon

```sh
# Detach into the background, export the socket + PID into the shell,
# and return control to the prompt — mirrors `ssh-agent` exactly.
eval $(gitway agent start -s)

# Now any client — gitway-add, ssh-add, ssh-keygen -Y sign — uses it:
gitway-add ~/.ssh/id_ed25519
ssh-add -l                    # OpenSSH's ssh-add talks to the Gitway agent
```

Without `-D`, `gitway agent start` respawns itself as a fully detached
session leader (new session via `setsid(2)`, ppid reparented to init,
stdio redirected to `/dev/null`). Use `-D` instead to stay in the
foreground — handy for debugging, systemd user units, or inline
`strace`. `-s` emits Bourne-shell `export` lines; `-c` emits csh/fish
`setenv` lines. With neither flag, Gitway picks based on `$SHELL`.

`-t <seconds>` sets a default lifetime — after that duration, the agent
silently evicts the key. Individual `gitway agent add -t <sec>`
requests override the daemon-wide default.

### Stopping it

```sh
gitway agent stop                       # reads $SSH_AGENT_PID or the pid file
```

### Running under systemd (optional)

A hardened user unit ships in
[`packaging/systemd/gitway-agent.service`](packaging/systemd/gitway-agent.service).
Install, enable, and point your shell at the socket:

```sh
mkdir -p ~/.config/systemd/user
cp packaging/systemd/gitway-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now gitway-agent.service

# add to .bashrc / .zshrc / config.fish
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/gitway-agent.sock"
```

The unit runs `gitway agent start -D` under a `@system-service` syscall
filter with read-only `$HOME`, private `/tmp`, and no new privileges —
see the file header for the full hardening list and how to change
`ExecStart=` if your `gitway` binary lives outside `/usr/local/bin`.

### Confirm-on-use keys (`gitway-add -c`)

Load a key with `-c` and the daemon asks for approval every time a
client tries to sign with it:

```sh
export SSH_ASKPASS=/usr/bin/ssh-askpass    # or ksshaskpass, etc.
gitway-add -c ~/.ssh/id_ed25519             # the -c matches ssh-add -c
```

The daemon invokes `$SSH_ASKPASS` with `SSH_ASKPASS_PROMPT=confirm`
when a sign request arrives; exit `0` from that program approves the
sign, anything else denies it. The same security rules as the
client-side passphrase flow apply — `SSH_ASKPASS` must be an absolute
path and must not be world-writable. If `SSH_ASKPASS` is unset or
misconfigured, confirm-required sign requests fail safe (deny) rather
than proceed unprompted. Running under systemd? `$SSH_ASKPASS` needs
to be in the unit's `Environment=` or the user session env that
started the unit — `systemctl --user import-environment SSH_ASKPASS
DISPLAY WAYLAND_DISPLAY XAUTHORITY` after logging in does the right
thing for GUI askpass binaries.

### Scope

- **Fully supported**: Ed25519, ECDSA (P-256, P-384, P-521), and RSA
  (`rsa-sha2-256` and `rsa-sha2-512`) sign operations. Cross-validated
  against real OpenSSH — `ssh-add`, `ssh-keygen -Y sign`, and `ssh`
  transport all accept Gitway-agent signatures unchanged. The legacy
  SHA-1 `ssh-rsa` wire algorithm is rejected; OpenSSH 8.2+ and every
  modern Git host request SHA-2 by default, so this only matters if
  you explicitly re-enable SHA-1 in your client config.
- **Windows**: the agent client and daemon both speak over named pipes
  (`\\.\pipe\gitway-agent.<PID>` by default, compatible with OpenSSH
  for Windows's `\\.\pipe\openssh-ssh-agent`). `gitway agent start -D`
  runs a foreground daemon; Ctrl+C triggers graceful shutdown. Background
  mode (no `-D`) and `gitway agent stop` are Unix-only — use
  `start /B`, `Stop-Process`, Task Manager, or a Windows service
  wrapper instead.

---

## Library usage

Add to `Cargo.toml`:

```toml
[dependencies]
gitway-lib = "0.8.0"
```

### Connect and run a Git command

```rust
use gitway_lib::{GitwayConfig, GitwaySession};

#[tokio::main]
async fn main() -> Result<(), gitway_lib::GitwayError> {
    let config = GitwayConfig::github();
    let mut session = GitwaySession::connect(&config).await?;
    session.authenticate_best(&config).await?;

    let exit_code = session.exec("git-upload-pack 'org/repo.git'").await?;
    session.close().await?;

    std::process::exit(exit_code as i32);
}
```

### Target a GitHub Enterprise Server instance

```rust
use gitway_lib::GitwayConfig;
use std::path::PathBuf;

let config = GitwayConfig::builder("ghe.corp.example.com")
    .port(22)
    .identity_file(PathBuf::from("/home/user/.ssh/id_ed25519"))
    .build();
```

### Handle errors by category

```rust
use gitway_lib::GitwayError;

fn handle(err: &GitwayError) {
    if err.is_host_key_mismatch() {
        eprintln!("Possible MITM — aborting.");
    } else if err.is_no_key_found() {
        eprintln!("No SSH key found. Pass --identity or start an SSH agent.");
    } else if err.is_authentication_failed() {
        eprintln!("Server rejected the key. Check your GitHub SSH key settings.");
    }
}
```

### `GitwayConfig` builder reference

| Method | Default | Description |
|---|---|---|
| `.port(u16)` | `22` | SSH port |
| `.username(str)` | `"git"` | Remote username |
| `.identity_file(path)` | none | Explicit private key path |
| `.cert_file(path)` | none | OpenSSH certificate path |
| `.skip_host_check(bool)` | `false` | Bypass fingerprint pinning |
| `.inactivity_timeout(Duration)` | `60 s` | Session idle timeout |
| `.custom_known_hosts(path)` | `~/.config/gitway/known_hosts` | GHE fingerprint file |
| `.fallback(Option<(String, u16)>)` | `ssh.github.com:443` | Port-22 fallback |

---

## Security

### Host-key pinning

Gitway embeds GitHub's published SHA-256 fingerprints for all three key types.
On every connection the server's key is hashed and compared against this list;
any mismatch aborts immediately with a `HostKeyMismatch` error.

Current fingerprints (verified 2026-04-05, [source](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)):

| Algorithm | SHA-256 fingerprint |
|---|---|
| Ed25519 | `SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU` |
| ECDSA | `SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM` |
| RSA | `SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s` |

If GitHub rotates its keys, update `hostkey.rs` and cut a patch release.

### Memory safety

Passphrase strings are wrapped in `Zeroizing<String>` and zeroed before the
allocation is released. Private key material in memory is managed by `russh`'s
`CryptoVec`, which zeroes its buffer on drop.

---

## Building from source

### Standard Linux, macOS, or WSL

```sh
git clone https://github.com/steelbore/gitway
cd gitway

# Requires a C compiler (gcc) for the aws-lc-rs cryptography crate.
cargo build --release
```

The release binary is at `target/release/gitway`.

### Shell-specific instructions

#### Nushell

```nu
git clone https://github.com/steelbore/gitway
cd gitway
cargo build --release
```

#### Ion

```ion
git clone https://github.com/steelbore/gitway
cd gitway
cargo build --release
```

#### Bash / Brush

```bash
git clone https://github.com/steelbore/gitway
cd gitway
cargo build --release
```

### NixOS

NixOS users should use the included `shell.nix` environment, which provides the correct C compiler and overrides problematic system RUSTFLAGS.

#### Nushell (recommended)

```nu
# Enter the dev shell interactively
nix-shell

# Then build inside the shell
cargo build --release

# Or run the build in one command
nix-shell --run 'cargo build --release'
```

#### Ion

```ion
# Enter the dev shell interactively
nix-shell

# Then build inside the shell
cargo build --release

# Or run the build in one command
nix-shell --run 'cargo build --release'
```

#### Bash / Brush

```bash
# Enter the dev shell interactively
nix-shell

# Then build inside the shell
cargo build --release

# Or run the build in one command
nix-shell --run 'cargo build --release'
```

#### Why nix-shell is required on NixOS

The default NixOS environment sets `RUSTFLAGS="-C target-cpu=x86-64-v4"`, which requires AVX-512 instructions not available on many CPUs. The `shell.nix` resets this to `-C target-cpu=native` and provides gcc without requiring global installation.

---

## Running the tests

**Unit tests and doc tests (all shells):**
```sh
cargo test
```

**Integration tests (require network access and a GitHub SSH key):**

*Nushell:*
```nu
$env.GITSSH_INTEGRATION_TESTS = "1"
cargo test --test test_connection
cargo test --test test_clone
```

*Ion:*
```ion
export GITSSH_INTEGRATION_TESTS=1
cargo test --test test_connection
cargo test --test test_clone
```

*Bash/Brush:*
```bash
GITSSH_INTEGRATION_TESTS=1 cargo test --test test_connection
GITSSH_INTEGRATION_TESTS=1 cargo test --test test_clone
```

---

## Acknowledgments

Gitway is built on **[russh](https://github.com/warp-tech/russh)**, a
pure-Rust SSH library originally written by
[Pierre-Étienne Meunier](https://github.com/P-E-Meunier) and maintained by
[Warp Technologies](https://warp.dev) and contributors.
russh is licensed under the Apache License 2.0.

The complete list of dependencies and their licences is in
[NOTICE.md](NOTICE.md).

---

## License

Copyright (C) 2026 Mohamed Hammad

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

See [LICENSE](LICENSE) for the full text.
