# NixOS VM Testing

The test verifies `ssh-guard` works end-to-end inside a NixOS VM with OpenSSH.

## VM tests

Test fixture at `nix/tests/ssh-guard-vm.nix` spins up a NixOS VM with:

- OpenSSH server + `ssh-guard` module enabled
- Pre-configured profiles to test allowed and denied commands

Scenarios covered:

| Scenario | What it checks |
| ------------------------------ | ------------------------------------------------------------------------- |
| **ForceCommand wiring** | OpenSSH invokes `ssh-guard run` as `ForceCommand` for matched users |
| **Allowed command** | User can execute a permitted command and get expected output |
| **Denied command** | User is blocked and receives a non-zero exit / rejection message |
| **Audit logging** | Denied/allowed events appear in configured audit log |
| **Stress / repeated attempts** | Service handles rapid sequential SSH command executions without degrading |

## Run the VM test directly

```sh
nix build .#checks.$(nix eval --raw --impure --expr 'builtins.currentSystem').ssh-guard-vm
```
