# Gitway — IDE Integration Guide

This guide explains how to configure Gitway as the SSH transport in common
development environments. The principle is the same everywhere: set
`GIT_SSH_COMMAND` (per session) or `core.sshCommand` (permanently in Git
config) to `gitway`.

---

## 1. Installation prerequisite

Build and install Gitway before configuring any IDE.

**Nushell:**
```nu
cargo install --path gitway-cli   # from source
# — or, once published —
cargo install gitway
```

**Ion:**
```ion
cargo install --path gitway-cli   # from source
# — or, once published —
cargo install gitway
```

**Bash/Brush:**
```bash
cargo install --path gitway-cli   # from source
# — or, once published —
cargo install gitway
```

Verify it is on your PATH (all shells):

```sh
gitway --test
# Hi <username>! You've successfully authenticated, but GitHub does not
# provide shell access.
```

Register it as the global Git SSH command so it works everywhere
automatically (all shells):

```sh
gitway --install
# Runs: git config --global core.sshCommand gitway
```

After `--install`, no IDE-specific configuration is needed in most cases.
The sections below cover environments that manage Git independently or need
additional steps.

---

## 2. Visual Studio Code

VS Code uses the system Git binary, which inherits `core.sshCommand` from
the global Git config set by `gitway --install`. No additional steps are
required after installation.

### Optional: per-workspace override

Add to `.vscode/settings.json`:

```json
{
  "git.path": "/usr/bin/git",
  "terminal.integrated.env.linux": {
    "GIT_SSH_COMMAND": "gitway"
  },
  "terminal.integrated.env.osx": {
    "GIT_SSH_COMMAND": "gitway"
  },
  "terminal.integrated.env.windows": {
    "GIT_SSH_COMMAND": "gitway"
  }
}
```

### Verifying in the VS Code terminal

Open the integrated terminal (**Terminal → New Terminal**) and run:

```sh
GIT_SSH_COMMAND=gitway git ls-remote git@github.com:your-org/your-repo.git
```

### Remote Development (SSH extension)

VS Code Remote SSH connects using OpenSSH, not Gitway. Gitway only applies
to **Git operations** (clone, fetch, push), not to the remote connection
itself.

---

## 3. Cursor

Cursor is a VS Code fork and uses the same Git integration. Follow the
**Visual Studio Code** steps above exactly — all settings paths are
identical.

After `gitway --install`, Cursor picks up `core.sshCommand = gitway` from
the global Git config automatically.

---

## 4. Zed

Zed uses the system Git binary and inherits environment variables from the
shell that launched it.

### Global configuration (recommended)

Run `gitway --install` once. Zed will use Gitway for all Git operations
automatically.

### Per-project configuration

In your project's `.zed/settings.json`:

```json
{
  "terminal": {
    "env": {
      "GIT_SSH_COMMAND": "gitway"
    }
  }
}
```

### Verifying in Zed's terminal

Open the terminal panel (**View → Terminal**) and run:

```sh
git fetch
```

If Gitway is active, the Git output pane will show normal operation without
an OpenSSH banner.

---

## 5. JetBrains IDEs

Covers: IntelliJ IDEA, PyCharm, WebStorm, GoLand, Rider, CLion, and all
other JetBrains products.

### Method A — Global Git config (recommended)

Run `gitway --install` once. JetBrains reads `core.sshCommand` from the
global Git config automatically for command-line Git operations.

### Method B — JetBrains SSH executable setting

JetBrains IDEs have their own SSH client for operations triggered from the
UI (VCS → Update Project, Push, etc.).  To route those through Gitway:

1. Open **Settings / Preferences** (`Ctrl+Alt+S` / `⌘,`).
2. Navigate to **Version Control → Git**.
3. Set **SSH executable** to **Native** (not the built-in client).
4. Confirm **Path to Git** points to your system `git` binary.

With **Native** SSH selected, JetBrains invokes `git` which in turn reads
`core.sshCommand = gitway` from the global config.

### Method C — Environment variable in the run configuration

For projects where the IDE manages its own environment:

1. Open **Settings → Tools → Terminal**.
2. Add to **Environment variables**: `GIT_SSH_COMMAND=gitway`.

Or add the variable to your shell profile so all processes launched by JetBrains inherit it:

- Nushell: `~/.config/nushell/config.nu`
- Ion: `~/.config/ion/initrc`
- Bash/Brush: `~/.bashrc` or `~/.bash_profile`

### Verifying in JetBrains

Open **VCS → Git → Fetch** and watch the **Git** tool-window log.
You should see the normal GitHub response without an OpenSSH
`Host key verification failed` warning.

---

## 6. Google Project IDX

Project IDX is a browser-based development environment built on Code OSS
(VS Code). It runs in a cloud VM where you can install binaries.

### Install inside the IDX environment

Open the IDX terminal and run:

```sh
# Install Rust if not already present
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Build and install gitway
cargo install gitway   # once published on crates.io
# — or from source —
git clone https://github.com/steelbore/gitssh && cargo install --path gitssh/gitway-cli
```

Then register it:

```sh
gitway --install
```

### Persist across VM restarts

Add to your `.idx/dev.nix` (IDX's environment configuration):

```nix
{ pkgs, ... }: {
  packages = [
    pkgs.rustup
  ];

  idx.workspace.onCreate = {
    install-gitssh = "cargo install gitway";
    configure-gitssh = "gitway --install";
  };
}
```

This reinstalls and configures Gitway every time the IDX VM is
provisioned or rebuilt.

### VS Code settings inside IDX

IDX inherits VS Code settings. Follow the **Visual Studio Code** section
for per-workspace configuration if needed.

---

## 7. GitHub Codespaces

Codespaces are Linux containers with Rust and Git pre-installed.

**Nushell:**
```nu
# In the Codespaces terminal:
cargo install gitway
gitway --install
```

**Ion:**
```ion
# In the Codespaces terminal:
cargo install gitway
gitway --install
```

**Bash/Brush:**
```bash
# In the Codespaces terminal:
cargo install gitway
gitway --install
```

To persist across container rebuilds, add to `.devcontainer/devcontainer.json`:

```json
{
  "postCreateCommand": "cargo install gitway && gitway --install"
}
```

Or use a `Dockerfile`:

```dockerfile
RUN cargo install gitway && gitway --install
```

---

## 8. NixOS-specific considerations

### Building from source on NixOS

NixOS requires the `shell.nix` environment due to incompatible default RUSTFLAGS.

**Nushell:**
```nu
cd /path/to/gitssh
nix-shell --run 'cargo install --path gitway-cli'
```

**Ion:**
```ion
cd /path/to/gitssh
nix-shell --run 'cargo install --path gitway-cli'
```

**Bash/Brush:**
```bash
cd /path/to/gitssh
nix-shell --run 'cargo install --path gitway-cli'
```

### IDE integration on NixOS

Most IDEs launched from the desktop environment will not have access to the nix-shell environment. To make `gitway` available system-wide after building:

**Nushell:**
```nu
# 1. Build with nix-shell
nix-shell --run 'cargo build --release'

# 2. Copy binary to PATH location
mkdir ~/.local/bin
cp target/release/gitssh ~/.local/bin/

# 3. Ensure ~/.local/bin is in PATH (add to ~/.config/nushell/env.nu)
$env.PATH = ($env.PATH | split row (char esep) | prepend ($env.HOME | path join .local bin))

# 4. Register globally
gitway --install
```

**Ion:**
```ion
# 1. Build with nix-shell
nix-shell --run 'cargo build --release'

# 2. Copy binary to PATH location
mkdir -p ~/.local/bin
cp target/release/gitssh ~/.local/bin/

# 3. Ensure ~/.local/bin is in PATH (add to ~/.config/ion/initrc)
export PATH="$HOME/.local/bin:$PATH"

# 4. Register globally
gitway --install
```

**Bash/Brush:**
```bash
# 1. Build with nix-shell
nix-shell --run 'cargo build --release'

# 2. Copy binary to PATH location
mkdir -p ~/.local/bin
cp target/release/gitssh ~/.local/bin/

# 3. Ensure ~/.local/bin is in PATH (add to ~/.bashrc or ~/.profile)
export PATH="$HOME/.local/bin:$PATH"

# 4. Register globally
gitway --install
```

### Alternative: Use direnv

For per-project IDE integration on NixOS, use [direnv](https://direnv.net/):

1. Install direnv: `nix-env -iA nixpkgs.direnv`

2. Create `.envrc` in your project root:
   ```bash
   use nix
   ```

3. Allow the directory: `direnv allow`

Now IDEs that support direnv (VS Code with the direnv extension, etc.) will automatically load the nix-shell environment.

---

## 9. Using Gitway as a library in IDE plugins

If you are building an IDE plugin or extension that embeds Rust and needs
Git transport, add `gitway-lib` as a dependency:

```toml
[dependencies]
gitway-lib = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
use gitssh_lib::{GitwayConfig, GitwaySession};

pub async fn fetch_pack(host: &str, repo: &str) -> Result<u32, gitssh_lib::GitwayError> {
    let config = GitwayConfig::builder(host).build();
    let mut session = GitwaySession::connect(&config).await?;
    session.authenticate_best(&config).await?;
    let exit = session.exec(&format!("git-upload-pack '{repo}'")).await?;
    session.close().await?;
    Ok(exit)
}
```

See [gitway-lib on docs.rs](https://docs.rs/gitway-lib) for the full API reference.

---

## 10. Troubleshooting

### `gitssh: command not found`

Gitway is not on your PATH. Ensure `~/.cargo/bin` is in `$PATH`:

**Nushell:**
```nu
$env.PATH = ($env.PATH | split row (char esep) | prepend ($env.HOME | path join .cargo bin))
# Add to ~/.config/nushell/env.nu for persistence
```

**Ion:**
```ion
export PATH="$HOME/.cargo/bin:$PATH"
# Add to ~/.config/ion/initrc for persistence
```

**Bash/Brush:**
```bash
export PATH="$HOME/.cargo/bin:$PATH"
# Add to ~/.bashrc or ~/.profile for persistence
```

### Host key mismatch

Gitway pins GitHub's known fingerprints. A mismatch means either:
- You are connecting to a non-GitHub SSH host (use `--custom-known-hosts`).
- A proxy or firewall is intercepting the connection.
- GitHub has rotated its keys (update Gitway to the latest version).

### No SSH key found

Gitway looks for keys in `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`,
`~/.ssh/id_rsa`, then asks the SSH agent. If none are found:

```sh
# Check your agent
ssh-add -l

# Add a key to the agent
ssh-add ~/.ssh/id_ed25519

# Or pass the key explicitly
git config --global core.sshCommand "gitway --identity ~/.ssh/id_ed25519"
```

### Passphrase prompt does not appear in IDE GUI

When a GUI app launches Git (GitHub Desktop, JetBrains, Zed, etc.), gitway
runs without a terminal. There are three solutions, in recommended order:

**Option 1 — SSH agent (recommended):** Load your key once per session.
Gitway always tries the agent first before asking for a passphrase.

```sh
ssh-add ~/.ssh/id_ed25519
```

**Option 2 — SSH_ASKPASS:** Point gitssh at a GUI passphrase dialog program.
Set these variables in your shell profile so they are inherited by GUI apps:

*Nushell (`~/.config/nushell/env.nu`):*
```nu
$env.SSH_ASKPASS = "/usr/bin/ksshaskpass"       # KDE
# $env.SSH_ASKPASS = "/usr/bin/ssh-askpass"     # GNOME / generic X11
$env.SSH_ASKPASS_REQUIRE = "prefer"
```

*Ion (`~/.config/ion/initrc`):*
```ion
export SSH_ASKPASS=/usr/bin/ksshaskpass
export SSH_ASKPASS_REQUIRE=prefer
```

*Bash/Brush (`~/.profile`):*
```bash
export SSH_ASKPASS=/usr/bin/ksshaskpass
export SSH_ASKPASS_REQUIRE=prefer
```

Common askpass programs by desktop environment:

| Desktop | Package | Binary |
|---|---|---|
| KDE (Plasma) | `ksshaskpass` | `/usr/bin/ksshaskpass` |
| GNOME | `ssh-askpass-gnome` | `/usr/bin/ssh-askpass-gnome` |
| Generic X11 | `openssh-askpass` | `/usr/bin/ssh-askpass` |
| NixOS (KDE) | `pkgs.ksshaskpass` | — |
| NixOS (X11) | `pkgs.x11_ssh_askpass` | — |

`SSH_ASKPASS_REQUIRE=prefer` tells gitssh to always use the GUI dialog when
`SSH_ASKPASS` is set (even if a terminal is present). Use `force` to override
terminal prompting entirely.

**Option 3 — run from the integrated terminal:** Open the IDE's built-in
terminal and perform the Git operation from there. The terminal is a real
TTY, so gitssh can prompt normally.
