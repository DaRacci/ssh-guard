# ssh-guard

ssh-guard is a restricted SSH command guard.
When a user connects, OpenSSH passes the command they typed in the environment variable.
ssh-guard reads that variable, matches it against a rule tree you define in a TOML config,
and only runs the command if it matches an allowed rule.

> Every attempt, logged and tested against your rules, keeping a trace of accountability be it a failure or success.

## What ssh-guard does

- Reads the command from `SSH_ORIGINAL_COMMAND`.
  If the variable is unset, ssh-guard exits with an error.
- If the command is empty or `help`, it prints the help output and exits `0`.
  `help_text` is used when set; otherwise help is generated from the rules.
- Commands are matched against rules. A match runs the command; a non-match is denied, _everything_ is logged.
- Rules can be scoped to profiles so different SSH users get different allowed commands.
- All actions are audited.

---

# Guides

- [ARCHITECTURE.md](docs/ARCHITECTURE.md): Developer guide to the code, extension points, and design invariants.
- [MANUAL_SETUP.md](docs/MANUAL_SETUP.md): How to install and configure ssh-guard on any Linux distribution.
- [NIXOS_SETUP.md](docs/NIXOS_SETUP.md): How to install and configure ssh-guard on NixOS.
- [CONFIGURATION.md](docs/CONFIG.md): How to write rules and configure ssh-guard.
- [SECURITY.md](docs/SECURITY.md): Security considerations for deploying ssh-guard.
- [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md): Common problems and how to fix them.
- [examples/README.md](examples/README.md): Example configs for Proxmox, systemd, web logs, PostgreSQL, and Nix hosts.
