# ssh-guard

ssh-guard is a restricted SSH command guard.
When a user connects, OpenSSH passes the command they typed in the environment variable.
ssh-guard reads that variable, matches it against a rule tree you define in a TOML config,
and only runs the command if it matches an allowed rule.

> Every attempt, logged and tested against your rules, keeping a trace of accountability be it a failure or success.

## What ssh-guard does

- Reads the command from `SSH_ORIGINAL_COMMAND`.
  If the variable is unset, ssh-guard exits with an error.
- If the command is empty, it prints the configured `help_text` and exits `0`.
- Commands are matched against rules. A match runs the command; a non-match is denied, _everything_ is logged.
- Rules can be scoped to profiles so different SSH users get different allowed commands.
- All actions are audited.

---

# Guides

- [MANUAL_SETUP.md](docs/MANUAL_SETUP.md): How to install and configure ssh-guard on any Linux distribution.
- [NIXOS_SETUP.md](docs/NIXOS_SETUP.md): How to install and configure ssh-guard on NixOS.
- [CONFIGURATION.md](docs/CONFIG.md): How to write rules and configure ssh-guard.
- [SECURITY.md](docs/SECURITY.md): Security considerations for deploying ssh-guard.
- [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md): Common problems and how to fix them.
