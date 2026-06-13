{
  self ? null,
}:
{
  config,
  pkgs,
  lib,
  ...
}:

let
  inherit (lib)
    mkIf
    mkOption
    mkEnableOption
    mkAfter
    types
    mapAttrsToList
    mapAttrs'
    nameValuePair
    filterAttrs
    attrNames
    attrValues
    concatStringsSep
    escapeShellArg
    optionalAttrs
    ;

  cfg = config.services.ssh-guard;
  tomlFormat = pkgs.formats.toml { };

  defaultPackage =
    if self != null
    then self.packages.${pkgs.system}.default or null
    else null;

  # For each profile, compute effective usernames
  # (list from `users` + attrNames from `managedUsers`)
  profileEffectiveUsers = mapAttrs' (
    pName: p:
    nameValuePair pName (p.users ++ attrNames p.managedUsers)
  ) cfg.profiles;

  # All usernames flat for duplicate detection
  allUsernames = lib.concatLists (attrValues profileEffectiveUsers);

  # Detect usernames bound to more than one profile
  userCounts = builtins.foldl' (
    acc: u: acc // { ${u} = (acc.${u} or 0) + 1; }
  ) { } allUsernames;
  duplicateUsers = filterAttrs (_: c: c > 1) userCounts;

  # Profiles with zero effective usernames
  emptyProfiles = filterAttrs (
    pName: users: users == [ ]
  ) profileEffectiveUsers;

  # Profiles with `users` in settings (forbidden — module auto-generates it)
  profilesWithUsersInSettings = filterAttrs (_: p: p.settings ? users) cfg.profiles;

  # Build profile TOML entry for a single profile
  mkProfileEntry = pName: p:
    let
      effectiveUsers = profileEffectiveUsers.${pName};
      usersAttr = optionalAttrs (effectiveUsers != [ ]) { users = effectiveUsers; };
    in
    usersAttr // p.settings;

  # Nix attrset for the `profiles` key (empty if no profiles)
  profilesAttr = optionalAttrs (cfg.profiles != { }) {
    profiles = mapAttrs' (
      pName: p: nameValuePair pName (mkProfileEntry pName p)
    ) cfg.profiles;
  };

  # Final single config to generate
  # cfg.settings is asserted to NOT contain `profiles`
  finalConfig = cfg.settings // profilesAttr;

  # Profiles with non-empty user list (for sshd Match blocks)
  profilesWithUsers = filterAttrs (_: users: users != [ ]) profileEffectiveUsers;

  # Build Match User block for sshd_config — all point at same config file
  sshdMatchBlock =
    pName: users:
    let
      configPath = "/etc/ssh-guard/config.toml";
      guardBin = "${lib.getBin cfg.package}/bin/ssh-guard";
    in
    ''
      Match User ${concatStringsSep "," users}
        ForceCommand ${escapeShellArg guardBin} run --config ${escapeShellArg configPath}
    '';

in
{
  options.services.ssh-guard = {
    enable = mkEnableOption "ssh-guard — restricted SSH command guard";

    package = mkOption {
      type = types.nullOr types.package;
      default = defaultPackage;
      defaultText =
        if self != null
        then "self.packages.\${pkgs.system}.default"
        else "null (must be set manually outside flake)";
      description = "ssh-guard package to use for ForceCommand.";
      example = lib.literalExpression "pkgs.ssh-guard";
    };

    settings = mkOption {
      inherit (tomlFormat) type;
      default = { };
      description = ''
        Base configuration for ssh-guard, written as TOML to
        {file}`/etc/ssh-guard/config.toml`.  Profile-local settings
        defined under {option}`profiles.<name>.settings` are merged into
        each profile entry inside the same file.

        Must not define a `profiles` key — profiles are declared via
        {option}`profiles` option instead.
      '';
      example = lib.literalExpression ''
        {
          global = {
            audit_log = "/var/log/ssh-guard.log";
            audit_format = "logfmt";
            log_tag = "ssh-guard";
          };
          roots = [ "/var/log" "/run" ];
          units = [ "sshd" "nginx" ];
        }
      '';
    };

    profiles = mkOption {
      type = types.attrsOf (
        types.submodule (
          { ... }:
          {
            options = {
              users = mkOption {
                type = types.listOf types.str;
                default = [ ];
                description = ''
                  SSH usernames (already existing on the system) that should be
                  matched by this profile's {command}`ForceCommand`.
                '';
                example = [
                  "alice"
                  "bob"
                ];
              };

              managedUsers = mkOption {
                type = types.attrsOf (
                  types.submodule (
                    { ... }:
                    {
                      options = {
                        authorizedKeys = mkOption {
                          type = types.listOf types.str;
                          default = [ ];
                          description = ''
                            SSH authorized public keys for this user.  The user
                            account is created minimally with only these keys.
                          '';
                          example = [ "ssh-ed25519 AAAA..." ];
                        };

                        authorizedKeyFiles = mkOption {
                          type = types.listOf types.path;
                          default = [ ];
                          description = "Files containing SSH authorized public keys.";
                        };
                      };
                    }
                  )
                );
                default = { };
                description = ''
                  Managed users created automatically by the module.  Each
                  attribute name becomes a {option}`users.users` entry with
                  only {option}`users.users.<name>.openssh.authorizedKeys` set.

                  For account customization (shell, groups, uid, etc.) use
                  {option}`users.users.<name>` directly.
                '';
                example = lib.literalExpression ''
                  {
                    git-runner = {
                      authorizedKeys = [ "ssh-ed25519 AAAA..." ];
                    };
                  }
                '';
              };

              settings = mkOption {
                inherit (tomlFormat) type;
                default = { };
                description = ''
                  Per-profile settings embedded in the profile entry of the
                  generated config file.  Values here override identically-named
                  keys in the base {option}`settings`.

                  Do not set `users` here — it is auto-generated from
                  {option}`users` and {option}`managedUsers`.
                '';
              };
            };
          }
        )
      );
      default = { };
      description = ''
        Named ssh-guard profiles.  Each profile produces:
        - A profile entry under `[profiles.<name>]` in the generated TOML config.
        - A `Match User` block in {file}`sshd_config` with
          `ForceCommand` pointing at the unified config file.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.package != null;
        message = ''
          ssh-guard: services.ssh-guard.package is not set.
          Either wire the flake or set it explicitly, e.g.
            services.ssh-guard.package = pkgs.ssh-guard;
        '';
      }
      {
        assertion = cfg.settings != { } || cfg.profiles != { };
        message = ''
          ssh-guard: services.ssh-guard is enabled but neither
          `settings` nor any `profiles` are configured.
        '';
      }
      {
        assertion = !(cfg.settings ? profiles);
        message = ''
          ssh-guard: services.ssh-guard.settings must not contain a `profiles`
          key.  Use the `services.ssh-guard.profiles` option instead.
        '';
      }
      {
        assertion = emptyProfiles == { };
        message = ''
          ssh-guard: the following profiles have no bound SSH usernames:
            ${concatStringsSep ", " (attrNames emptyProfiles)}
          Each profile must set `users` or `managedUsers`.
        '';
      }
      {
        assertion = cfg.profiles == { } || (config.services ? openssh && config.services.openssh.enable);
        message = ''
          ssh-guard: profiles are defined but services.openssh.enable is not set.
          ssh-guard requires OpenSSH to install ForceCommand rules.
        '';
      }
      {
        assertion = profilesWithUsersInSettings == { };
        message = ''
          ssh-guard: the following profiles have `users` in their `settings`:
            ${concatStringsSep ", " (attrNames profilesWithUsersInSettings)}
          The `users` field is auto-generated from the profile's
          `users` and `managedUsers` options.
        '';
      }
      {
        assertion = duplicateUsers == { };
        message = ''
          ssh-guard: the following SSH usernames appear in more than one profile:
            ${concatStringsSep ", " (attrNames duplicateUsers)}
          Each SSH user must belong to exactly one profile.
        '';
      }
    ];

    environment.systemPackages = lib.optional (cfg.package != null) cfg.package;

    environment.etc."ssh-guard/config.toml".source =
      tomlFormat.generate "ssh-guard-config.toml" finalConfig;

    users.users = lib.mkMerge (
      mapAttrsToList (
        _: p:
        mapAttrs' (
          uName: u:
          nameValuePair uName {
            openssh.authorizedKeys.keys = u.authorizedKeys;
            openssh.authorizedKeys.keyFiles = u.authorizedKeyFiles;
          }
        ) p.managedUsers
      ) cfg.profiles
    );

    services.openssh = mkIf (profilesWithUsers != { }) {
      extraConfig = mkAfter (
        concatStringsSep "\n" (
          mapAttrsToList (
            pName: users: sshdMatchBlock pName users
          ) profilesWithUsers
        )
      );
    };
  };
}
