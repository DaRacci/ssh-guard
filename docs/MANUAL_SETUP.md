# Setup Guide

This guide walks through installing and configuring ssh-guard manually.
It covers building the binary, writing a config, wiring it into OpenSSH,
and verifying it works.

For the security considerations that matter during setup, see [SECURITY.md](SECURITY.md).
For help with common problems, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## Table of Contents

1. [Build the binary](#build-the-binary)
1. [Install the binary](#install-the-binary)
1. [Wire it into SSH](#wire-it-into-ssh)
1. [Validate the config](#validate-the-config)
1. [Verify it works end-to-end](#verify-it-works-end-to-end)
1. [Summary of setup steps](#summary-of-setup-steps)

---

## Build the binary

From the repository root:

```sh
cargo build --release
```

The binary is produced at `target/release/ssh-guard`.

### Run the test suite

Before deploying from source, run the unit and integration tests to verify the current build is healthy:

```sh
cargo test
```

---

## Install the binary

Copy the binary to a system location and make it executable:

```sh
sudo install -m 0755 target/release/ssh-guard /usr/local/bin/ssh-guard
```

Verify:

```sh
ssh-guard --help
```

---

## Wire it into SSH

There are two common ways to route SSH commands through ssh-guard.
Choose the one that fits your setup.

### Per-key `command=` in `authorized_keys`

For each key that should be restricted, prefix its line in `~/.ssh/authorized_keys` with a `command=` directive:

```
command="/usr/local/bin/ssh-guard run --config /etc/ssh-guard/config.toml",no-pty,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

When that key connects, OpenSSH runs `ssh-guard run` instead of the user's shell, and passes the typed command via `SSH_ORIGINAL_COMMAND`.

### Global `ForceCommand` in `sshd_config`

Apply to all matching connections in `/etc/ssh/sshd_config`:

```sshd_config
Match Group restricted
    ForceCommand /usr/local/bin/ssh-guard run --config /etc/ssh-guard/config.toml
```

> **Note:** `ForceCommand` overrides the `command=` in `authorized_keys` and any shell.
> Use `Match` blocks to scope it to specific users/groups.

### Recommended `sshd_config` hardening for restricted accounts

```conf
Match Group restricted
    ForceCommand /usr/local/bin/ssh-guard run --config /etc/ssh-guard/config.toml
    PermitTTY no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
```

After editing, reload sshd:

```sh
sudo systemctl reload sshd
```

---

## Validate the config

Before relying on it, validate the config.
The `validate` subcommand checks binary paths, symlink handling, and duplicate users:

```sh
ssh-guard validate --config /etc/ssh-guard/config.toml
```

Expected output on success:

```
Validating config: /etc/ssh-guard/config.toml
Config is valid. N base rule(s), M profile rule(s) (T total).
```

If there are problems, it prints each error and exits non-zero.
Common validation failures:

- `binary '...' does not exist`: the `run` binary path is wrong.
- `binary '...' is a symlink -> '...' (implicit_symlinks disabled)`: set `implicit_symlinks = true` or use the real path.
- `duplicate user '...' in profiles '...' and '...'`: a user is listed in more than one profile.

---

## Verify it works end-to-end

### 1. Confirm the audit log is writable

During execution ssh-guard appends to the path specific for `audit_log`.
Ensure all users that will run the guard can write to this location.

```sh
touch /var/log/ssh-guard-audit.log
tee /var/log/ssh-guard-audit.log <<< "test"
tail -n 1 /var/log/ssh-guard-audit.log
```

### 2. Test the guard directly

You can simulate what OpenSSH does by setting `SSH_ORIGINAL_COMMAND` and running the guard:

```sh
SSH_ORIGINAL_COMMAND="systemctl status sshd" \
  ssh-guard run --config /etc/ssh-guard/config.toml
```

You should see the `systemctl status sshd` output.

### 3. Test a denied command

```sh
SSH_ORIGINAL_COMMAND="rm -rf /" \
  ssh-guard run --config /etc/ssh-guard/config.toml
```

This should fail with `no matching rule` and exit non-zero.

### 4. Check the audit log

```sh
tail -n 20 /var/log/ssh-guard-audit.log
```

You should see one `allowed` entry for the `systemctl status sshd` test and one `denied` entry for the `rm -rf /` test.

### 5. Validate the SSH Command routing

From another machine:

```sh
ssh restricted-user@your-host "systemctl status sshd"
```

This should run the allowed command. Then try something not allowed:

```sh
ssh restricted-user@your-host "rm -rf /"
```

This should be denied. Confirm both appear in the audit log.
