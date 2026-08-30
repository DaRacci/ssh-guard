# Troubleshooting

Common problems when setting up and running ssh-guard, and how to fix them.

---

## Common issues

| Symptom | Likely cause / fix |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `no SSH_ORIGINAL_COMMAND set` | The guard was run directly without OpenSSH. This is expected when without `SSH_ORIGINAL_COMMAND` environment variable set. |
| `cannot read config file` | Wrong `--config` path, or the file is unreadable by the guard's user. |
| `no matching rule` on a command you expect to work | The rule tree doesn't cover that command. Check subcommand names, flags, and args. |
| `binary '...' does not exist` | Wrong binary path in the `run` action. Run `validate`. |
| Audit log has no entries | The guard can't write the log, or the log path is wrong. Check ownership and test with a direct run. |
| `duplicate user ...` | A user is listed in more than one profile. Remove the duplicate profile entry. |
| SSH still drops into a shell | The `command=`/`ForceCommand` isn't applied to that key/session. Check `authorized_keys` and `sshd_config`, then `systemctl reload sshd`. |
| Command hangs | The rule's `timeout` may be too long, or the command legitimately blocks. Lower the timeout. |
