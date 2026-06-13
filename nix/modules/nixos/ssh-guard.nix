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
    mkMerge
    mkOption
    mkEnableOption
    mkAfter
    types
    recursiveUpdate
    mapAttrsToList
    mapAttrs'
    nameValuePair
    filterAttrs
    attrNames
    concatStringsSep
    escapeShellArg
    ;

  cfg = config.services.ssh-guard;
  tomlFormat = pkgs.formats.toml { };

  defaultPackage = if self != null then self.packages.${pkgs.system}.default or null else null;

  # Profiles with enable = true
  enabledProfiles = filterAttrs (_: p: p.enable) cfg.profiles;

  # Build list of { profile, user } records for dedup + sshd config
  profileUsers = builtins.concatLists (
    mapAttrsToList (
      pName: p:
      (map (u: {
        profile = pName;
        user = u;
      }) p.matchUsers)
      ++ mapAttrsToList (uName: _: {
        profile = pName;
        user = uName;
      }) (filterAttrs (_: u: u.enable or true) p.users)
    ) enabledProfiles
  );

  allUsernames = map (x: x.user) profileUsers;

  # Detect usernames bound to more than one profile
  userCounts = builtins.foldl' (acc: u: acc // { ${u} = (acc.${u} or 0) + 1; }) { } allUsernames;
  duplicateUsers = filterAttrs (_: c: c > 1) userCounts;

  # Profiles with zero effective bound usernames (respects per-user enable)
  emptyProfiles = filterAttrs (
    pName: _: !(usersByProfile ? ${pName} && usersByProfile.${pName} != [ ])
  ) enabledProfiles;

  # Merge base settings with per-profile overrides
  profileConfig = profile: recursiveUpdate cfg.settings profile.settings;

  # Build Match User block for sshd_config
  sshdMatchBlock =
    profileName: users:
    let
      configPath = "/etc/ssh-guard/profiles/${profileName}.toml";
      guardBin = "${lib.getBin cfg.package}/bin/ssh-guard";
    in
    ''
      Match User ${concatStringsSep "," users}
        ForceCommand ${escapeShellArg guardBin} run --config ${escapeShellArg configPath}
    '';

  # Group usernames per profile for compact Match blocks
  usersByProfile = builtins.foldl' (
    acc: pu: acc // { ${pu.profile} = (acc.${pu.profile} or [ ]) ++ [ pu.user ]; }
  ) { } profileUsers;

  # Profiles that actually have users to match
  profilesWithUsers = filterAttrs (
    pName: _: usersByProfile ? ${pName} && usersByProfile.${pName} != [ ]
  ) enabledProfiles;

in
{
  options.services.ssh-guard = {
    enable = mkEnableOption "ssh-guard — restricted SSH command guard";

    package = mkOption {
      type = types.nullOr types.package;
      default = defaultPackage;
      defaultText =
        if self != null then
          "self.packages.\${pkgs.system}.default"
        else
          "null (must be set manually outside flake)";
      description = "ssh-guard package to use for ForceCommand.";
      example = lib.literalExpression "pkgs.ssh-guard";
    };

    settings = mkOption {
      inherit (tomlFormat) type;
      default = { };
      description = ''
        Base configuration for ssh-guard, written as TOML to
        {file}`/etc/ssh-guard/config.toml`.  Every profile merges these
        settings with its own per-profile overrides.
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
          { name, ... }:
          {
            options = {
              enable = mkOption {
                type = types.bool;
                default = true;
                description = "Whether this profile is active.";
              };

              settings = mkOption {
                inherit (tomlFormat) type;
                default = { };
                description = ''
                  Per-profile settings merged on top of
                  {option}`services.ssh-guard.settings`.  Values here override
                  base settings with the same attribute path.
                '';
              };

              matchUsers = mkOption {
                type = types.listOf types.str;
                default = [ ];
                description = ''
                  SSH usernames (already existing on the system) that should be
                  matched by this profile's `ForceCommand`.
                '';
                example = [
                  "alice"
                  "bob"
                ];
              };

              users = mkOption {
                type = types.attrsOf (
                  types.submodule (
                    _:
                    {
                      options = {
                        enable = mkOption {
                          type = types.bool;
                          default = true;
                          description = "Whether this managed user is created.";
                        };

                        authorizedKeys = mkOption {
                          type = types.listOf types.str;
                          default = [ ];
                          description = "SSH authorized public keys for this user.";
                          example = [ "ssh-ed25519 AAAA..." ];
                        };

                        authorizedKeyFiles = mkOption {
                          type = types.listOf types.path;
                          default = [ ];
                          description = "Files containing SSH authorized public keys.";
                        };

                        description = mkOption {
                          type = types.str;
                          default = "ssh-guard managed user";
                          description = "GECOS description for the user.";
                        };

                        home = mkOption {
                          type = types.nullOr types.str;
                          default = null;
                          description = "Home directory. Defaults to {file}`/var/empty`.";
                        };

                        createHome = mkOption {
                          type = types.bool;
                          default = false;
                          description = "Whether to create the home directory.";
                        };

                        group = mkOption {
                          type = types.nullOr types.str;
                          default = null;
                          description = "Primary group. Defaults to a group named after the user.";
                        };

                        extraGroups = mkOption {
                          type = types.listOf types.str;
                          default = [ ];
                          description = "Supplementary groups for this user.";
                        };

                        uid = mkOption {
                          type = types.nullOr types.ints.unsigned;
                          default = null;
                          description = "UID for the user. Assigns automatically if null.";
                        };

                        packages = mkOption {
                          type = types.listOf types.package;
                          default = [ ];
                          description = "Packages to add to the user's environment.";
                        };

                        shell = mkOption {
                          type = types.nullOr types.package;
                          default = pkgs.bashInteractive;
                          defaultText = lib.literalExpression "pkgs.bashInteractive";
                          description = ''
                            Login shell.  Defaults to {command}`bash` so it is valid
                            for forced-command use.
                          '';
                        };

                        isNormalUser = mkOption {
                          type = types.bool;
                          default = true;
                          description = ''
                            Whether to create a normal (non-system) user account.
                          '';
                        };
                      };
                    }
                  )
                );
                default = { };
                description = ''
                  Managed users created automatically by the module.  Each
                  attribute name becomes a {option}`users.users` entry.
                '';
                example = lib.literalExpression ''
                  {
                    gitops = {
                      authorizedKeys = [ "ssh-ed25519 AAAA..." ];
                      extraGroups = [ "docker" ];
                    };
                  }
                '';
              };
            };
          }
        )
      );
      default = { };
      description = ''
        Named ssh-guard profiles.  Each profile produces:
        - A TOML config at {file}`/etc/ssh-guard/profiles/<name>.toml`
          (base settings merged with per-profile overrides).
        - A `Match User` block in {file}`sshd_config` with
          `ForceCommand` pointing to its config.
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
        assertion = cfg.settings != { } || enabledProfiles != { };
        message = ''
          ssh-guard: services.ssh-guard is enabled but neither
          `settings` nor any `profiles` are configured.
        '';
      }
      {
        assertion = emptyProfiles == { };
        message = ''
          ssh-guard: the following profiles have no bound SSH usernames:
            ${concatStringsSep ", " (attrNames emptyProfiles)}
          Each enabled profile must set `matchUsers` or `users`.
        '';
      }
      {
        assertion = enabledProfiles == { } || (config.services ? openssh && config.services.openssh.enable);
        message = ''
          ssh-guard: profiles are defined but services.openssh.enable is not set.
          ssh-guard requires OpenSSH to install ForceCommand rules.
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

    # --- Package in PATH for manual validation ---
    environment.systemPackages = lib.optional (cfg.package != null) cfg.package;

    # --- Config file generation ---
    environment.etc = mkMerge [
      (mkIf (cfg.settings != { }) {
        "ssh-guard/config.toml".source = tomlFormat.generate "ssh-guard-config.toml" cfg.settings;
      })

      (mkIf (enabledProfiles != { }) (
        mapAttrs' (
          pName: p:
          nameValuePair "ssh-guard/profiles/${pName}.toml" {
            source = tomlFormat.generate "ssh-guard-profile-${pName}.toml" (profileConfig p);
          }
        ) enabledProfiles
      ))
    ];

    # --- Managed users ---
    users.users = mkMerge (
      mapAttrsToList (
        _: p:
        mapAttrs' (
          uName: u:
          nameValuePair uName {
            inherit (u)
              isNormalUser
              description
              uid
              shell
              createHome
              packages
              extraGroups
              ;
            home =
              if u.home != null then
                u.home
              else if u.isNormalUser then
                "/home/${uName}"
              else
                "/var/empty";
            group =
              if u.group != null then
                u.group
              else if u.isNormalUser then
                uName
              else
                "nogroup";
            openssh.authorizedKeys.keys = u.authorizedKeys;
            openssh.authorizedKeys.keyFiles = u.authorizedKeyFiles;
          }
        ) (filterAttrs (_: u: u.enable or true) p.users)
      ) enabledProfiles
    );

    # --- Auto-created groups for managed users with no explicit group ---
    users.groups = mkMerge (
      mapAttrsToList (
        _: p:
        mapAttrs' (
          uName: u:
          let
            gName = if u.group != null then u.group else uName;
          in
          nameValuePair gName { }
        ) (filterAttrs (_: u: (u.enable or true) && u.group == null && u.isNormalUser) p.users)
      ) enabledProfiles
    );

    # --- SSHD integration ---
    services.openssh = mkIf (profilesWithUsers != { }) {
      extraConfig = mkAfter (
        concatStringsSep "\n" (
          mapAttrsToList (pName: _: sshdMatchBlock pName usersByProfile.${pName}) profilesWithUsers
        )
      );
    };
  };
}
