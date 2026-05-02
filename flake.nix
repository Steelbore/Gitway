# SPDX-License-Identifier: GPL-3.0-or-later
# Nix flake for gitway.
#
# Usage:
#   nix build                         # build the release binary
#   nix run                           # run gitway directly
#   nix develop                       # enter the development shell
#   nix build .#gitway                # explicit package name
#
# Install into your NixOS system or home-manager profile:
#   nix profile install github:steelbore/gitway
{
  description = "Pure-Rust SSH toolkit for Git: transport, keys, signing, agent";

  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      # Pull the version from the workspace Cargo.toml so the flake never
      # drifts behind a release.  Cargo.toml is the single source of truth
      # for `workspace.package.version`.
      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

      mkGitway = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname   = "gitway";
        version = cargoToml.workspace.package.version;

        src = self;

        # Use the checked-in Cargo.lock for reproducible builds.
        cargoLock.lockFile = ./Cargo.lock;

        # Build the CLI binary crate, which emits all three of its `[[bin]]`
        # targets: `gitway`, `gitway-keygen`, and `gitway-add`.  The default
        # installPhase picks up every executable under `target/release/`.
        cargoBuildFlags = [ "-p" "gitway" ];
        cargoTestFlags  = [ "--workspace" ];

        # aws-lc-rs non-FIPS build: requires perl for the assembly pre-processing
        # step. cmake and go are NOT required for non-FIPS builds.
        nativeBuildInputs = with pkgs; [
          perl
        ];

        # Modern nixpkgs exposes the Darwin SDK automatically via
        # `stdenv`, so pure-Rust crates with the `aws-lc-rs` crypto
        # backend don't need explicit `apple_sdk.frameworks.*` inputs
        # (the legacy stubs were removed in 2025).

        meta = {
          description = "Pure-Rust SSH toolkit for Git: transport, keys, signing, agent";
          homepage    = "https://github.com/steelbore/gitway";
          license     = pkgs.lib.licenses.gpl3Plus;
          # TODO: once the upstream maintainer (github.com/UnbreakableMJ) has a
          # `pkgs.lib.maintainers` entry, list it here.  Nix has no Windows
          # target for this derivation so platforms stays unix-only.
          maintainers = [ ];
          mainProgram = "gitway";
          platforms   = pkgs.lib.platforms.unix;
        };
      };
    in
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs   = nixpkgs.legacyPackages.${system};
        gitway = mkGitway pkgs;
      in
      {
        # ── Packages ───────────────────────────────────────────────────────────
        packages = {
          gitway  = gitway;
          default = gitway;
        };

        # ── Run ────────────────────────────────────────────────────────────────
        apps.default = flake-utils.lib.mkApp {
          drv  = gitway;
          name = "gitway";
        };

        # ── Development shell ──────────────────────────────────────────────────
        # Supersedes shell.nix; shell.nix delegates here for backward
        # compatibility with `nix-shell` users.
        devShells.default = pkgs.mkShell {
          name = "gitway-dev";

          nativeBuildInputs = with pkgs; [
            # Rust toolchain via rustup so developers can pin versions freely.
            rustup

            # Required by the aws-lc-rs crate (assembly pre-processing).
            perl

            # C toolchain for linking.
            gcc

            # Optional: strip release binaries.
            binutils

            # Convenience: git, cargo-edit, etc.
            git
          ];

          # Override NixOS-injected CFLAGS that break aws-lc-rs's C build:
          # the stdenv injects `-flto=auto`, which produces GCC LTO IR
          # objects the Rust linker can't resolve.  RUSTFLAGS is left to
          # flow through from the ambient environment (e.g. the user's
          # NixOS host) so host-level CPU targeting takes effect.
          CFLAGS = "-march=native -O2 -pipe";

          shellHook = ''
            echo "gitway dev shell ready. Run: cargo build --release"
          '';
        };
      }
    )) // {
      # ── home-manager module ────────────────────────────────────────────────
      #
      # Exposes `services.gitway-agent.enable` so home-manager users can run
      # the Gitway SSH agent as a per-user systemd service without copying
      # `packaging/systemd/gitway-agent.service` by hand.  The socket lands
      # at `$XDG_RUNTIME_DIR/gitway-agent.sock`; `home.sessionVariables`
      # points `SSH_AUTH_SOCK` at it for every child shell.
      #
      # Usage (in home-manager config):
      #
      #   imports = [ gitway.homeManagerModules.default ];
      #   services.gitway-agent.enable = true;
      homeManagerModules.default = { config, pkgs, lib, ... }:
        let
          cfg     = config.services.gitway-agent;
          gitway  = mkGitway pkgs;
        in
        {
          options.services.gitway-agent = {
            enable = lib.mkEnableOption "Gitway SSH agent user service";

            package = lib.mkOption {
              type        = lib.types.package;
              default     = gitway;
              defaultText = lib.literalExpression "gitway.packages.\${system}.default";
              description = "The gitway package to use for the agent.";
            };

            defaultLifetime = lib.mkOption {
              type        = lib.types.nullOr lib.types.int;
              default     = null;
              example     = 3600;
              description = ''
                Default TTL (seconds) applied to every key added to the agent.
                `null` disables the default TTL; per-key overrides via
                `gitway-add -t <sec>` still work.
              '';
            };

            extraArgs = lib.mkOption {
              type        = lib.types.listOf lib.types.str;
              default     = [ ];
              example     = [ "--verbose" ];
              description = "Extra arguments passed to `gitway agent start`.";
            };
          };

          config = lib.mkIf cfg.enable {
            home.packages = [ cfg.package ];

            # SSH_AUTH_SOCK needs to reach two audiences:
            #
            #   1. `.profile`-sourced interactive shells — login bash/zsh,
            #      Nushell's env config, terminals that source `~/.profile`.
            #      `home.sessionVariables` covers this path.
            #
            #   2. Every child of `systemd --user` — GUI git clients launched
            #      via the desktop session, non-interactive subshells spawned
            #      by tools like Claude Code, cron / timers, other user
            #      services.  These inherit their environment from the
            #      systemd user manager, which reads `environment.d(5)` files
            #      at session start.
            #
            # Setting only (1) leaves non-interactive children of the user
            # session unable to find the agent — they fall back to prompting
            # for the passphrase and fail with no TTY attached.  Writing both
            # closes that gap.  The literal `${XDG_RUNTIME_DIR}` is expanded
            # by the shell / systemd-environment-d-generator at session
            # start, not by Nix (hence the `''${...}'' ` escape).
            home.sessionVariables.SSH_AUTH_SOCK = "\${XDG_RUNTIME_DIR}/gitway-agent.sock";

            xdg.configFile."environment.d/10-gitway-agent.conf".text = ''
              SSH_AUTH_SOCK=''${XDG_RUNTIME_DIR}/gitway-agent.sock
            '';

            systemd.user.services.gitway-agent = {
              Unit = {
                Description   = "Gitway SSH agent (user)";
                Documentation = "https://github.com/steelbore/gitway";
                # Running alongside OpenSSH's user ssh-agent would race on
                # SSH_AUTH_SOCK; refuse if both are enabled.
                Conflicts = [ "ssh-agent.service" ];
              };

              Service = {
                Type      = "simple";
                ExecStart = lib.concatStringsSep " " (
                  [
                    "${cfg.package}/bin/gitway"
                    "agent" "start"
                    "-D" "-s"
                    "-a" "%t/gitway-agent.sock"
                  ]
                  ++ lib.optionals (cfg.defaultLifetime != null)
                       [ "-t" (toString cfg.defaultLifetime) ]
                  ++ cfg.extraArgs
                );
                Restart    = "on-failure";
                RestartSec = 2;

                # Hardening — mirrors packaging/systemd/gitway-agent.service.
                # The agent holds private key material; strip every capability
                # and filesystem surface it does not need.
                #
                # `ProtectHome=read-only` covers `/home`, `/root`, AND
                # `/run/user/` per systemd(5) — the socket path
                # `%t/gitway-agent.sock` lives under `/run/user/$UID`, so
                # without the `ReadWritePaths=%t` explicit grant the agent
                # bind(2) fails with `EROFS` and the unit crash-loops.
                NoNewPrivileges         = true;
                ProtectSystem           = "strict";
                ProtectHome             = "read-only";
                ReadWritePaths          = [ "%t" ];
                PrivateTmp              = true;
                PrivateDevices          = true;
                ProtectKernelTunables   = true;
                ProtectKernelModules    = true;
                ProtectKernelLogs       = true;
                ProtectControlGroups    = true;
                ProtectClock            = true;
                ProtectHostname         = true;
                RestrictNamespaces      = true;
                RestrictRealtime        = true;
                RestrictSUIDSGID        = true;
                LockPersonality         = true;
                MemoryDenyWriteExecute  = true;
                SystemCallArchitectures = "native";
                SystemCallFilter        = "@system-service";
                SystemCallErrorNumber   = "EPERM";
              };

              Install.WantedBy = [ "default.target" ];
            };
          };
        };

      # ── NixOS module ───────────────────────────────────────────────────────
      #
      # Same shape as the home-manager module but wired as a system-scoped
      # NixOS module — installs the package into `environment.systemPackages`
      # and registers the hardened user unit via `systemd.user.services`.
      # Enable with `services.gitway-agent.enable = true;` in your NixOS
      # configuration.
      nixosModules.default = { config, pkgs, lib, ... }:
        let
          cfg    = config.services.gitway-agent;
          gitway = mkGitway pkgs;
        in
        {
          options.services.gitway-agent = {
            enable = lib.mkEnableOption "Gitway SSH agent user service";

            package = lib.mkOption {
              type        = lib.types.package;
              default     = gitway;
              defaultText = lib.literalExpression "gitway.packages.\${system}.default";
              description = "The gitway package to use for the agent.";
            };
          };

          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];

            # System-wide `environment.d(5)` file so every user's systemd
            # user manager exports SSH_AUTH_SOCK — reaches non-interactive
            # subshells (Claude Code, scripts with `-c`), GUI git clients
            # launched via the desktop session, cron / timers, and other
            # user services.  The literal `${XDG_RUNTIME_DIR}` is expanded
            # by systemd-environment-d-generator at session start, not by
            # Nix.
            environment.etc."environment.d/10-gitway-agent.conf".text = ''
              SSH_AUTH_SOCK=''${XDG_RUNTIME_DIR}/gitway-agent.sock
            '';

            systemd.user.services.gitway-agent = {
              description = "Gitway SSH agent (user)";
              wantedBy    = [ "default.target" ];
              conflicts   = [ "ssh-agent.service" ];

              serviceConfig = {
                Type       = "simple";
                ExecStart  = "${cfg.package}/bin/gitway agent start -D -s -a %t/gitway-agent.sock";
                Restart    = "on-failure";
                RestartSec = 2;

                # `ProtectHome=read-only` covers `/run/user/` — without
                # `ReadWritePaths=%t`, the agent cannot bind(2) its socket
                # at `$XDG_RUNTIME_DIR/gitway-agent.sock` and crash-loops
                # with `EROFS`.
                NoNewPrivileges         = true;
                ProtectSystem           = "strict";
                ProtectHome             = "read-only";
                ReadWritePaths          = [ "%t" ];
                PrivateTmp              = true;
                PrivateDevices          = true;
                ProtectKernelTunables   = true;
                ProtectKernelModules    = true;
                ProtectKernelLogs       = true;
                ProtectControlGroups    = true;
                ProtectClock            = true;
                ProtectHostname         = true;
                RestrictNamespaces      = true;
                RestrictRealtime        = true;
                RestrictSUIDSGID        = true;
                LockPersonality         = true;
                MemoryDenyWriteExecute  = true;
                SystemCallArchitectures = "native";
                SystemCallFilter        = "@system-service";
                SystemCallErrorNumber   = "EPERM";
              };
            };
          };
        };
    };
}
