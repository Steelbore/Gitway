---
name: gitway
description: SSH transport client for Git hosting services (GitHub, GitLab, Codeberg)
version: "0.3.0"
commands:
  - name: gitway --test
    description: Verify SSH connectivity and authentication to a Git host
    supports_json: true
    idempotent: true
    flags:
      - name: --host
        description: Target hostname (default github.com)
        type: string
      - name: --json
        description: Emit structured JSON result
        type: boolean
      - name: --verbose
        description: Enable debug logging to stderr
        type: boolean
  - name: gitway --install
    description: Register gitway as git core.sshCommand globally
    supports_json: true
    idempotent: true
    flags:
      - name: --json
        description: Emit structured JSON result
        type: boolean
  - name: gitway schema
    description: Emit JSON Schema for all Gitway commands
    supports_json: true
    idempotent: true
  - name: gitway describe
    description: Emit capability manifest for agent/CI discovery
    supports_json: true
    idempotent: true
constraints:
  - Requires a valid SSH key (ed25519, ecdsa, or rsa) or an SSH agent
  - Host key verification is enforced for known providers; cannot be disabled without --insecure-skip-host-check
  - Passphrase prompting requires a terminal or SSH_ASKPASS helper
exit_codes:
  0: Success
  1: General / unexpected error
  2: Usage error (bad arguments or configuration)
  3: Not found (no identity key, unknown host)
  4: Permission denied (authentication failure, host key mismatch)
---
