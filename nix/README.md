# ssh-guard NixOS Module

Restricted SSH command guard, manage SSH forced-command profiles and users declaratively.

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
        matchUsers = [ "root" "deploy" ];
        settings.roots = [ "/" ];
      };

      # Profile with managed users
      gitops = {
        users.git-runner = {
          authorizedKeys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop"
          ];
          extraGroups = [ "docker" ];
        };
      };
    };
  };
}
```

## What it does

| Behaviour | Detail |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Config files** | `/etc/ssh-guard/config.toml` generated from `settings` (if non-empty). |
| **Profile files** | `/etc/ssh-guard/profiles/<name>.toml` per enabled profile (base settings merged with per-profile overrides). |
| **SSH forced commands** | Each profile appends a `Match User` / `ForceCommand` block to `services.openssh.extraConfig` pointing `ssh-guard run --config` at its profile TOML. |
| **Managed users** | Profile `users.<name>` create `users.users` entries with `authorizedKeys`, groups, shell, home, etc. |
| **Duplicate guard** | Assertion fails if an SSH user appears in more than one profile. |
