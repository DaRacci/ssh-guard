# Security Guide

This document covers the security considerations that matter when deploying and running ssh-guard.

---

## The `command=` / `ForceCommand` wrapper is the enforcement point

ssh-guard only runs when OpenSSH actually invokes it.
The security boundary is the `command=` directive or `ForceCommand`.
If a user can reach a shell or another program that bypasses the guard, the restriction is meaningless.
Apply `command=` to every key that should be restricted, or scope `ForceCommand` with a `Match` block

## Restrict the SSH session, not just the command

A restricted command guard is not a full sandbox.
Even with the guard in place, harden the session via traditional SSH hardening techniques:

- `PermitTTY no`: prevents interactive shells.
- Disable agent, TCP, and X11 forwarding.
- Consider `no-port-forwarding`, `no-agent-forwarding`, `no-X11-forwarding` in `authorized_keys` options.
- Give restricted users a dedicated group.

> **Note on login shells:** OpenSSH invokes `ForceCommand`/`command=` via the user's login shell with the `-c` option.
> The login shell must therefore be able to run commands.
> Do not set the login shell to `nologin` or `/bin/false` for a guarded user, or the guard itself will fail to start.

## The config file must be protected

The config defines what commands are allowed.
Anyone who can edit it can grant themselves arbitrary commands. Protect it with root ownership and restrictive permissions:

```sh
sudo chown root:root /etc/ssh-guard/config.toml
sudo chmod 0644 /etc/ssh-guard/config.toml
```

> **Note:** the guard runs as the SSH user, not as root, so the config must be readable by that user.
> `0644` is world-readable but still root-owned and only root-writable, the security boundary is integrity, not confidentiality.
> The only thing world-read exposes is the allowlist policy, which is low-value since an SSH user can already probe what is allowed.

## The audit log must be append-only and protected

The audit log is the record of who ran what.
If a user can freely edit it, they can erase their tracks.
The guard runs as the SSH user, so the log must be writable by any user but it should be append-only writable and not readable.

```sh
sudo touch /var/log/ssh-guard-audit.log
sudo chown root:root /var/log/ssh-guard-audit.log
sudo chmod 0222 /var/log/ssh-guard-audit.log   # make it world writable
sudo chattr +a /var/log/ssh-guard-audit.log    # set append-only attribute
```

> **Why `0222`:** the guard opens the log with `append(true)` and only ever appends, so all users need write access but not read access.
> `0222` grants write to everyone with no read bits, keeping the log unreadable by the audited users.
> `root` can always read it regardless of the permission bits.
>
> **Why `+a`:** the append-only attribute protects integrity.
> Existing entries can't be modified, truncated, or deleted, and the file can't be renamed or removed.

## Profile selection trusts `USER`

ssh-guard picks the effective profile from the `USER` environment variable.
Under a normal OpenSSH `ForceCommand`/`command=` session, OpenSSH sanitizes the environment and sets `USER` to the authenticated login name, so this is safe.
However if the guard is ever invoked outside such a session from a shell, cron, or any process where the caller controls the environment, the caller can set `USER` to match a privileged profile and inherit its rules.

Keep the guard reachable only through OpenSSH's forced-command path, and do not run it from attacker-influenced contexts.

## Audit write failures are silent

ssh-guard appends audit events but does not fail the command if the write fails.
If the audit log becomes unwritable, has incorrect permissions, the disk is full, or other fs issues,
the command still runs and the event is silently dropped.
An attacker who can make the log unwritable could evade auditing.

Monitor the audit log's writability and disk space, and treat a missing or
stale log as an incident rather than an inconvenience.

> **Note:** This is a known limitation and is planned to be addressed.

## Use absolute binary paths and verify them

`run` actions execute a fixed `binary` path.
The use of absolute paths is required (e.g. `/usr/bin/systemctl`, not `systemctl`) so a compromised `PATH` cannot redirect execution.
The `validate` subcommand checks that the binary exists, and with `implicit_symlinks` enabled,
symlinked binaries are canonicalized to their real path before execution, which prevents symlink-swap attacks on the binary.
If you set `implicit_symlinks = false`, `validate` will raise an error due to the symlinked binaries.

## File actions are confined to `roots`

The actions `read_file`, `tail_file`, `stat_path`, and `list_dir` resolve the target path and reject it unless it is within one of the configured `roots`.
Keep `roots` as narrow as possible.
Do not add broad roots like `/` unless you intend to expose the whole filesystem.

## Timeouts prevent runaway commands

`run` actions have a `timeout` field.
On timeout, ssh-guard kills the entire process group and all children with `SIGKILL`.
Set reasonable timeouts per rule so an allowed command cannot hang indefinitely.

## Attempts are audited

Every attempt that reaches rule matching is logged to the audit log before any command is executed.
An allowed command produces a `started` event (before execution) and an `allowed` event (after it completes);
a denied command produces a `denied` event with the rejection reason.

> **Note:** a command that fails to parse (e.g. unbalanced quotes) or a missing `SSH_ORIGINAL_COMMAND`
> returns an error without writing an audit event.

Review the audit log regularly, a spike in denials can indicate probing or a misconfigured rule.

## `add-rule` rewrites the config

The `add-rule` subcommand reads, merges, and writes the config file back.
It is a convenience for scaffolding, not a security boundary, you should always review the resulting TOML.

> **Note:** `add-rule` does not validate the config after writing, a misconfigured rule can break the guard.
> Always Run `validate` after any `add-rule` operation.

## Profiles: a user must match at most one

If a user matches multiple profiles, `resolve_for_user` returns an error and the command is denied.
The `validate` subcommand catches duplicate users across profiles.
Keep profile membership unambiguous.

## The guard is not a sandbox

ssh-guard restricts _which_ commands run; it does not sandbox _what_ those commands can do.
An allowed command like `systemctl` or `journalctl` runs with the privileges of the SSH user.
Grant only the commands the user genuinely needs, and prefer the least-privileged account possible.

## Do not guard the root user

ssh-guard is designed for dedicated, least-privilege accounts, not for `root`.
Applying the guard to `root` is a bad idea for several reasons:

- **Root is a single point of failure.**
  If the guard misbehaves, the config is wrong, or the binary is broken, you can lock yourself out of the only account that can fix it.
  A dedicated restricted user can be recreated or bypassed without losing administrative access.
- **Least privilege is undermined.**
  The whole point of the guard is to limit what a compromised session can do.
  Any command allowed to run as root runs with full system privileges, so a single overly-broad rule becomes a root-equivalent escape hatch.

Instead, create dedicated users, give each only the commands it needs.
If you must allow some privileged operations, scope them to a dedicated account with the narrowest possible rule set.

If you update the binary or change the config, re-run `validate` and re-test an allowed and a denied command.
A stale config can silently allow or deny the wrong things.
