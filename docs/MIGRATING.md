# Migration Guide

Breaking config changes between releases, and how to update an existing config.

Config paths, rule matching, and actions are covered in [CONFIG.md](CONFIG.md).

---

## From 0.3

Two config keys accepted up to 0.3.0 were removed in 0.4.0, and one default
changed. The parser warns about none of them, so update existing configs after
upgrading.

### Generated help is served by default

Up to 0.3.0, an empty command or `help` printed `help_text` and nothing else.

In 0.4.0, when `help_text` is empty the guard prints generated help instead.
That listing enumerates contract `enum` values, integer ranges, and the paths in
every configured root set. `generated_help` defaults to `true`, so upgrading
exposes the listing to any connecting user without any further action.

Set `generated_help = false` to print only `help_text` (an empty line when unset,
as before), or write a curated listing into `help_text`.
See [SECURITY.md](SECURITY.md#generated-help-can-disclose-policy).

### `show_help` action removed

The `show_help` action is gone: `help` and an empty command are now handled automatically (see [Actions](CONFIG.md#actions)), so the rule is redundant. Delete it.

A config that still contains `type = "show_help"` **fails to parse**, because `show_help` is no longer a valid action variant. Under `ForceCommand` that means every SSH command fails until the rule is removed.
`ssh-guard validate` reports the unknown variant and points back to this guide.

```diff
 [[rules]]
-command = "help"
-action = { type = "show_help" }
```

### `units` removed

The top-level `units` array and the per-profile `units` override are gone.
Both were informational only, so delete them. Because the config parser ignores unknown keys, a leftover `units = [...]` loads silently and has no effect — `ssh-guard validate` will not flag it.

```diff
-units = ["sshd.service", "nginx.service"]
-
 [global]
 audit_log = "/var/log/ssh-guard-audit.log"
```
