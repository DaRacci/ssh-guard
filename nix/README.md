# ssh-guard NixOS Module

Restricted SSH command guard, manage declarative SSH forced-command profiles.

## Usage

Add flake input:

```nix
{
  inputs = {
    ssh-guard.url = "github:your-org/ssh-guard";
  };
}
```

Import module:

```nix
{
  imports = [ inputs.ssh-guard.nixosModules.default ];
}
```

## Example

```nix
{
  services.openssh.enable = true;

  services.ssh-guard = {
    enable = true;

    settings = {
      global = {
        audit_log = "/var/log/ssh-guard.log";
        log_tag = "ssh-guard";
      };
      roots = [ "/var/log" "/run" ];
    };

    profiles = {
      # Profile matching existing system users
      admin = {
        users = [ "root" "deploy" ];
        settings.roots = [ "/" ];
      };

      # Profile with managed users
      gitops = {
        managedUsers.git-runner = {
          authorizedKeys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop"
          ];
        };
      };
    };
  };
}
```

## What it does

| Behaviour               | Detail                                                                                                                                                     |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Config file**         | Single `/etc/ssh-guard/config.toml` generated from `settings` with embedded `[profiles.<name>]` sections.                                                  |
| **SSH forced commands** | Each profile appends a `Match User` / `ForceCommand` block to `services.openssh.extraConfig` pointing `ssh-guard run --config /etc/ssh-guard/config.toml`. |
| **Managed users**       | `profiles.<name>.managedUsers.<name>` entries create minimal `users.users` entries with authorized keys only. No `isNormalUser`, `home`, `group`, etc. set by module. |
| **User dedup**          | Assertion fails if an SSH user appears in more than one profile.                                                                                           |

## Options

| Option                                   | Type                  | Description                                          |
| ---------------------------------------- | --------------------- | ---------------------------------------------------- |
| `services.ssh-guard.enable`              | `bool`                | Enable the ssh-guard module.                         |
| `services.ssh-guard.package`             | `package`             | ssh-guard package for ForceCommand.                  |
| `services.ssh-guard.settings`            | TOML attrset          | Base config written to `/etc/ssh-guard/config.toml`. |
| `services.ssh-guard.profiles`            | attrset of submodules | Named profiles (attr presence = enabled).            |
| `profiles.<name>.users`                  | `list of string`      | Existing SSH usernames matched by this profile.      |
| `profiles.<name>.managedUsers`           | attrset of submodules | Users created automatically by the module.           |
| `managedUsers.<name>.authorizedKeys`     | `list of string`      | SSH authorized public keys.                          |
| `managedUsers.<name>.authorizedKeyFiles` | `list of path`        | Files with authorized public keys.                   |
| `profiles.<name>.settings`               | TOML attrset          | Per-profile config merged into the profile entry.    |

## Notes

- **No `enable` per profile** - profile exists if declared.
- **User account extras** (group, shell, uid, extraGroups, home, packages) are intentionally **not** exposed by this module. Use `users.users.<name>` directly.
- Module sets **only** `openssh.authorizedKeys.*` on managed user entries. No `isNormalUser`, `home`, `group`, etc.
- OpenSSH must be enabled (`services.openssh.enable = true`) when any profiles are defined.

## Testing

### Purpose of `nix/` subtree

Contains NixOS module definition (`nix/modules/nixos/ssh-guard.nix`), VM integration test (`nix/tests/ssh-guard-vm.nix`), and this README. The test verifies `ssh-guard` works end-to-end inside a NixOS VM with OpenSSH - not just unit-level Rust behavior.

### VM test - what it validates

Test fixture at `nix/tests/ssh-guard-vm.nix` spins up a NixOS VM with:

- OpenSSH server + `ssh-guard` module enabled
- Pre-configured profiles (allowed and denied commands)

Scenarios covered:

| Scenario | What it checks |
|---|---|
| **ForceCommand wiring** | OpenSSH invokes `ssh-guard run` as `ForceCommand` for matched users |
| **Allowed command** | User can execute a permitted command and get expected output |
| **Denied command** | User is blocked and receives a non-zero exit / rejection message |
| **Audit logging** | Denied/allowed events appear in configured audit log |
| **Stress / repeated attempts** | Service handles rapid sequential SSH command executions without degrading |

### Run the VM test directly

```bash
# Run just the ssh-guard VM test (once flake is wired)
nix build .#checks.$(nix eval --raw --impure --expr 'builtins.currentSystem').ssh-guard-vm

# Or use nix flake check to run all checks
nix flake check
```

The flake exposes this test under `checks.<system>.ssh-guard-vm`. If the test name differs in your branch, check the `checks` attribute in the flake output.

### Broader validation

```bash
# All checks (VM test + any future tests)
nix flake check --keep-going

# Individual parts
nix build .#packages.$(nix eval --raw --impure --expr 'builtins.currentSystem').default
```

### If the test fails

1. **Check test definition** - `nix/tests/ssh-guard-vm.nix`. Look for assertion logic, SSH key setup, or profile misconfig.
2. **Inspect the VM** - Re-run with `nix run` instead of `nix build` to get an interactive shell, or add `interactive = true;` to the test node.
3. **Check audit log path** - Default location set in the test's `services.ssh-guard.settings.global.audit_log`. Verify event entries are present.
4. **Check OpenSSH config** - The `ForceCommand` line in the VM's `/etc/ssh/sshd_config` should point to the correct `ssh-guard` binary and config path.
5. **Run Rust test suite** - `cargo test` for unit/integration tests independent of NixOS.
