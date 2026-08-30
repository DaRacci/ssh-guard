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
        users = [ "service" ];
        settings.roots = [ "/lib/service" ];
      };

      # Profile matching a dedicated least-privilege account
      gitops = {
        users = [ "git-runner" ];
      };
    };

    users.users.git-runner = {
      isNormalUser = true;
      openssh.authorizedKeys.keys = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop"
      ];
    };
  };
}
```

## What it does

| Behaviour | Detail |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Config file** | Single `/etc/ssh-guard/config.toml` generated from `settings` with embedded `[profiles.<name>]` sections. |
| **SSH forced commands** | Each profile appends a `Match User` / `ForceCommand` block to `services.openssh.extraConfig` pointing `ssh-guard run --config /etc/ssh-guard/config.toml`. |
| **User deduplication** | Assertion fails if an SSH user appears in more than one profile. |
| **Missing users** | Warning if a profile references a user not defined in `users.users`. |
| **Login shell check** | Assertion fails if a profile user's `shell` is `nologin` or `false`; the guard is invoked via the login shell and would fail to start. |

## Options

| Option | Type | Description |
| ---------------------------------------- | --------------------- | ---------------------------------------------------- |
| `services.ssh-guard.enable` | `bool` | Enable the ssh-guard module. |
| `services.ssh-guard.package` | `package` | ssh-guard package for ForceCommand. |
| `services.ssh-guard.settings` | TOML attrset | Base config written to `/etc/ssh-guard/config.toml`. |
| `services.ssh-guard.profiles` | attrset of submodules | Named profiles. |
| `profiles.<name>.users` | `list of string` | SSH usernames matched by this profile. Must exist in `users.users`. |
| `profiles.<name>.settings` | TOML attrset | Per-profile config merged into the profile entry. |
