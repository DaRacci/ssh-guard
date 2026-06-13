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

- **No `enable` per profile** — profile exists if declared.
- **User account extras** (group, shell, uid, extraGroups, home, packages) are intentionally **not** exposed by this module. Use `users.users.<name>` directly.
- Module sets **only** `openssh.authorizedKeys.*` on managed user entries. No `isNormalUser`, `home`, `group`, etc.
- OpenSSH must be enabled (`services.openssh.enable = true`) when any profiles are defined.
