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
    mapAttrs'
    mapAttrsToList
    nameValuePair
    filterAttrs
    attrNames
    attrValues
    concatStringsSep
    escapeShellArg
    optionalAttrs
    filter
    literalExpression
    ;

  cfg = config.services.ssh-guard;
  tomlFormat = pkgs.formats.toml { };

  auditLog = cfg.settings.global.audit_log or "/var/log/ssh-guard-audit.log";
  defaultPackage = if self != null then self.packages.${pkgs.system}.default or null else null;
  profileEffectiveUsers = mapAttrs' (pName: p: nameValuePair pName p.users) cfg.profiles;
  allUsernames = lib.concatLists (attrValues profileEffectiveUsers);

  # OpenSSH invokes ForceCommand via the user's login shell with `-c`, so the shell must be able to run commands.
  # A nologin/false shell would make the guard itself fail to start.
  isNologinShell = s: lib.hasSuffix "/nologin" s || lib.hasSuffix "/false" s;

  missingUsers = filter (u: !(config.users.users ? "${u}")) allUsernames;
  nologinShellUsers = filter (
    u: config.users.users ? "${u}" && isNologinShell config.users.users.${u}.shell
  ) allUsernames;

  userCounts = builtins.foldl' (acc: u: acc // { ${u} = (acc.${u} or 0) + 1; }) { } allUsernames;
  duplicateUsers = filterAttrs (_: c: c > 1) userCounts;

  emptyProfiles = filterAttrs (pName: users: users == [ ]) profileEffectiveUsers;
  profilesWithUsersInSettings = filterAttrs (_: p: p.settings ? users) cfg.profiles;

  mkProfileEntry =
    pName: p:
    let
      effectiveUsers = profileEffectiveUsers.${pName};
      usersAttr = optionalAttrs (effectiveUsers != [ ]) { users = effectiveUsers; };
    in
    usersAttr // p.settings;

  profilesAttr = optionalAttrs (cfg.profiles != { }) {
    profiles = mapAttrs' (pName: p: nameValuePair pName (mkProfileEntry pName p)) cfg.profiles;
  };

  finalConfig = cfg.settings // profilesAttr;

  profilesWithUsers = filterAttrs (_: users: users != [ ]) profileEffectiveUsers;

  sshdMatchBlock =
    pName: users:
    let
      configPath = "/etc/ssh-guard/config.toml";
      guardBin = "${lib.getExe cfg.package}";
    in
    ''
      Match User ${concatStringsSep "," users}
        PermitTTY no
        AllowTcpForwarding no
        AllowAgentForwarding no
        X11Forwarding no
        ForceCommand ${escapeShellArg guardBin} run --config ${escapeShellArg configPath}
    '';

in
{
  options.services.ssh-guard = {
    enable = mkEnableOption "ssh-guard, a restricted SSH command guard";

    package = mkOption {
      type = types.nullOr types.package;
      default = defaultPackage;
      defaultText = if self != null then "self.packages.\${pkgs.system}.default" else "null";
      description = "ssh-guard package to use for ForceCommand.";
      example = literalExpression "pkgs.ssh-guard";
    };

    settings = mkOption {
      inherit (tomlFormat) type;
      default = { };
      description = ''
        Base configuration for ssh-guard, written as TOML to {file}`/etc/ssh-guard/config.toml`.
        Profile-local settings defined under {option}`profiles.<name>.settings` are merged into each profile entry inside the same file.

        Do not define `profiles` here, they are declared via {option}`profiles` option instead.
      '';
      example = literalExpression ''
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
        types.submodule (_: {
          options = {
            users = mkOption {
              type = types.listOf types.str;
              default = [ ];
              description = ''
                Usernames that should be matched by this profile's {command}`ForceCommand`.
                These users must exist in {option}`users.users` already.
              '';
              example = [
                "alice"
                "bob"
              ];
            };

            settings = mkOption {
              inherit (tomlFormat) type;
              default = { };
              description = ''
                Per-profile settings embedded in the profile entry of the
                generated config file.  Values here override identically-named
                keys in the base {option}`settings`.

                Do not set `users` here - it is auto-generated from
                {option}`users`.
              '';
            };
          };
        })
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
          `services.ssh-guard.package` is not set, and no default package is available.
        '';
      }
      {
        assertion = cfg.settings != { } || cfg.profiles != { };
        message = ''
          `services.ssh-guard` is enabled but neither `settings` nor any `profiles` are configured.
        '';
      }
      {
        assertion = !(cfg.settings ? profiles);
        message = ''
          `services.ssh-guard.settings` must not contain a `profiles` key.
          Use the `services.ssh-guard.profiles` option instead.
        '';
      }
      {
        assertion = emptyProfiles == { };
        message = ''
          the following profiles have no bound SSH usernames:
            ${concatStringsSep ", " (attrNames emptyProfiles)}
          Each `services.ssh-guard.profile.<name>` must set `users`.
        '';
      }
      {
        assertion = cfg.profiles == { } || (config.services ? openssh && config.services.openssh.enable);
        message = ''
          profiles are defined but `services.openssh.enable` is not set.
          ssh-guard requires OpenSSH to install ForceCommand rules.
        '';
      }
      {
        assertion = profilesWithUsersInSettings == { };
        message = ''
          the following profiles have `users` in their `settings`:
            ${concatStringsSep ", " (attrNames profilesWithUsersInSettings)}
          The `users` field is auto-generated from the profile's `users` option, and must not be set in `settings`.
        '';
      }
      {
        assertion = duplicateUsers == { };
        message = ''
          the following SSH usernames appear in more than one profile:
            ${concatStringsSep ", " (attrNames duplicateUsers)}
          Each SSH user must belong to exactly one profile.
        '';
      }
      {
        assertion = nologinShellUsers == [ ];
        message = ''
          the following SSH users have a login shell that cannot run commands:
            ${concatStringsSep ", " nologinShellUsers}
          users must have `users.users.<name>.shell` set to a shell that can run commands, e.g. `pkgs.bash`.
        '';
      }
      {
        assertion = lib.hasPrefix "/" auditLog;
        message = ''
          the audit log path must be absolute, got: ${auditLog}
        '';
      }
    ];

    warnings = lib.mkIf (missingUsers != [ ]) [
      ''
        the following SSH users referenced in profiles do not exist as NixOS users:
          ${concatStringsSep ", " missingUsers}
        The Match User / ForceCommand block will still be generated, but these users cannot log in.
        Define them in `users.users`, or remove them from the profile.
      ''
    ];

    environment.systemPackages = [ cfg.package ];

    environment.etc."ssh-guard/config.toml".source =
      tomlFormat.generate "ssh-guard-config.toml" finalConfig;

    systemd.tmpfiles.rules = [
      "f ${auditLog} 0222 root root -"
      "h ${auditLog} - - - -"
    ];

    services.openssh = mkIf (profilesWithUsers != { }) {
      extraConfig = mkAfter (
        concatStringsSep "\n" (mapAttrsToList (pName: users: sshdMatchBlock pName users) profilesWithUsers)
      );
    };
  };
}
