{ self, pkgs }:

let
  inherit (pkgs) lib testers;

  sshGuardPackage = self.packages.${pkgs.system}.default;
  sshGuardModule = import ../modules/nixos/ssh-guard.nix { inherit self; };

  clientKey = pkgs.runCommandLocal "ssh-guard-test-client-key" {
    nativeBuildInputs = [ pkgs.openssh ];
  } ''
    mkdir -p "$out"
    ssh-keygen -t ed25519 -N "" -f "$out/id_ed25519"
    chmod 644 "$out/id_ed25519.pub"
  '';
in

testers.runNixOSTest {
  name = "ssh-guard-vm";

  nodes.server = { pkgs, lib, ... }: {
    imports = [ sshGuardModule ];

    services.openssh = {
      enable = true;
      settings = {
        PasswordAuthentication = false;
        PermitRootLogin = "no";
      };
    };

    services.ssh-guard = {
      enable = true;
      package = sshGuardPackage;

      settings = {
        global = {
          audit_log = "/tmp/ssh-guard-audit.log";
          audit_format = "logfmt";
          help_text = ''
            Allowed commands: echo
          '';
        };
      };

      profiles.main = {
        managedUsers.testuser = {
          authorizedKeyFiles = [ "${clientKey}/id_ed25519.pub" ];
        };
        settings = {
          rules = [
            {
              command = "echo";
              args = [ "{string}" ];
              action = {
                type = "run";
                binary = "${lib.getBin pkgs.coreutils}/bin/echo";
                args = [ ];
                timeout = "5s";
              };
            }
          ];
        };
      };
    };

    users.users.testuser = {
      isNormalUser = true;
      home = "/home/testuser";
      shell = pkgs.bash;
    };

    environment.etc."ssh-guard-test/id_ed25519".source = "${clientKey}/id_ed25519";
  };

  testScript = ''
    server.start()
    server.wait_for_unit("sshd")
    server.wait_for_unit("network.target")
    server.wait_for_open_port(22)

    key = "/root/.ssh/id_ed25519"
    server.succeed("mkdir -p /root/.ssh && cp /etc/ssh-guard-test/id_ed25519 " + key + " && chmod 600 " + key)

    opts = (
      "-o StrictHostKeyChecking=no "
      "-o UserKnownHostsFile=/dev/null "
      "-o LogLevel=ERROR "
      f"-i {key}"
    )

    # let sshd settle after boot
    server.sleep(2)

    with subtest("allowed command succeeds and produces expected output"):
      out = server.succeed(f"ssh {opts} testuser@localhost 'echo hello_from_ssh_guard'")
      assert "hello_from_ssh_guard" in out, f"expected hello_from_ssh_guard in output, got: {out}"

    with subtest("denied command fails with non-zero exit"):
      rc, out = server.execute(f"ssh {opts} testuser@localhost 'cat /etc/passwd'")
      assert rc != 0, f"denied command should fail, got rc={rc}"

    with subtest("case variant does not bypass guard"):
      rc, out = server.execute(f"ssh {opts} testuser@localhost 'ECHO world'")
      assert rc != 0, f"case variant should be denied, got rc={rc}"

    with subtest("audit log records allowed and denied attempts"):
      audit_text = server.succeed("cat /tmp/ssh-guard-audit.log")
      assert "allowed" in audit_text, "audit log missing 'allowed' entry"
      assert "denied" in audit_text, "audit log missing 'denied' entry"
      assert "hello_from_ssh_guard" in audit_text, "audit log missing command text"
      assert "cat /etc/passwd" in audit_text or "cat" in audit_text, "audit log missing denied command text"

    with subtest("burst of rapid SSH attempts"):
      for i in range(5):
        server.succeed(f"ssh {opts} testuser@localhost 'echo hello'")
        rc, _ = server.execute(f"ssh {opts} testuser@localhost 'whoami'")
        assert rc != 0, f"whoami should be denied on attempt {i}"

    with subtest("audit log grew with burst entries"):
      audit_wc = server.succeed("wc -l /tmp/ssh-guard-audit.log")
      line_count = int(audit_wc.strip().split()[0])
      assert line_count >= 13, f"audit log too small: {line_count} lines (expected >= 13)"
  '';
}
