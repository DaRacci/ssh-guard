# Configuration Reference

This document describes how to write the ssh-guard TOML config: the top-level sections, `[global]` options, rules, actions, templates and contracts, and profiles.

The config file path is resolved in order of precedence:

1. `--config` argument
1. `SSH_GUARD_CONFIG` environment variable
1. default path `/etc/ssh_guard/config.toml`

---

## Minimal config

```toml
[global]
audit_log = "/var/log/ssh-guard-audit.log"
audit_format = "json"
help_text = """
Allowed commands:
  systemctl status <unit>
  journalctl -n <lines>
"""

[[rules]]
action = { type = "run", binary = "/usr/bin/systemctl", args = [], timeout = "5s" }
implicit_symlinks = true

[[rules.subcommands]]
name = "status"
args = ["{string}.service"]
```

---

## Config anatomy

The config has these top-level sections:

| Section | Purpose |
| ------------------- | ------------------------------------------------------------------------------ |
| `[global]` | Global settings: audit log, help text, limits, syslog tag. |
| `[contracts]` | Named value constraints (`int_range`, `string_len`, `enum`) used in templates. |
| `[flag_groups]` | Named groups of flags reused across rules/subcommands. |
| `[[rules]]` | Allowed command rules. |
| `roots` | Allowed filesystem roots for file/path actions. |
| `units` | Allowed systemd units (informational; used by templates). |
| `[profiles.<name>]` | Per-user overrides that extend the base config. |

---

## `[global]` options

| Key | Default | Description |
| -------------------- | ------------------------------ | ----------------------------------------------- |
| `audit_log` | `/var/log/ssh-guard-audit.log` | File all audit events are appended to. |
| `audit_format` | `json` | `json` or `logfmt`. |
| `help_text` | _(empty)_ | Shown when the SSH command is empty. |
| `log_tag` | `ssh-guard` | Syslog tag for non-audit logging. |
| `max_read_bytes` | `1048576` | Max bytes a `read_file` action will output. |
| `max_tail_lines` | `5000` | Hard cap on lines for `tail_file`. |
| `default_tail_lines` | `200` | Default lines for `tail_file` when unspecified. |

---

## Rules

Each `[[rules]]` entry has:

| Key | Default | Description |
| ------------------- | ------------------------ | ------------------------------------------------------------------------------------------ |
| `action` | _(required)_ | What to do. See below. |
| `command` | derived from binary name | First token users must type to match. Required for non-`run` actions. |
| `implicit_symlinks` | `true` | If true, allows the use of paths pointing to a symlink, otherwise will result in an error. |
| `arg_style` | `gnu_long` | `gnu_long`, `posix_short`, or `dos`. |
| `flag_groups` | `[]` | Named flag groups applied at this level. |
| `flags` | `[]` | Allowed flags at this level. |
| `args` | `[]` | Allowed arguments (literals, templates, inline flags). |
| `pre_args` | `[]` | Static args injected before user argv. Placeholders `{name}` / `{name:-default}` are substituted from match captures. |
| `subcommands` | `[]` | Nested subcommand rules. |

### Actions

| Action | Fields | Behavior |
| ----------- | ------------------------------------------------------------ | -------------------------------------- |
| `run` | `binary`, `args`, `timeout` | Runs the binary with the matched argv. |
| `read_file` | `path_capture`, `root_set` | Prints a file's contents. |
| `tail_file` | `path_capture`, `lines_capture`, `default_lines`, `root_set` | Tails a file. |
| `stat_path` | `path_capture`, `root_set` | Prints path metadata. |
| `list_dir` | `path_capture`, `root_set` | Lists a directory. |
| `show_help` | — | Prints `help_text`. |

`timeout` accepts strings like `"5s"`, `"5000ms"`, `"2m"`, `"1.5h"`, or a bare integer in milliseconds.
The Default is set to `5000ms`.

---

## Templates and contracts

Arguments can use templates like `{string}`, `{int}`, `{any}`, `{port}`, and inline templates like `--depth={int}` or `{unit}.service`.
Named contracts defined in `[contracts]` constrain template values:

```toml
[contracts.port]
type = "int_range"
min = 1024
max = 65535

[contracts.unit]
type = "enum"
values = ["sshd", "nginx"]
```

### Capture names

Every template argument captures its matched value so file actions can reference it:

| Arg pattern | Capture name |
| -------------------- | ------------------------- |
| `{name:template}` | `name` (explicit, preferred) |
| `{contract}` | the contract's name |
| `{string}` / `{int}` / `{any}` | positional (`arg_0`, `arg_1`, ...) |

Use explicit named captures when a file action needs the value:

```toml
[[rules]]
action = { type = "read_file", path_capture = "path", root_set = "roots" }
command = "cat"
args = ["{path:string}"]
```

`path_capture` / `lines_capture` accept the name with or without braces,
"path" or "{path}" both resolve to a capture named `path`.

Note: bare builtins like `{string}` capture positionally, so
`path_capture = "{string}"` can never resolve.
`ssh-guard validate` rejects such configs at load time with an error naming the field.

### Template substitution in `action.args` and `pre_args`

Match captures also resolve placeholders in config-sourced strings: `action.args` and `pre_args` (rule-level and subcommand) support `{name}` and `{name:-default}`.
This lets a rule pin argument structure, for example bounding `du` recursion depth server-side:

```toml
[[rules]]
action = { type = "run", binary = "/usr/bin/du", args = ["-d{depth:-1}"], timeout = "30s" }
command = "du"
args = ["{path}"]
```

Substitution rules:

- `{name}` resolves from the capture that matched at match time.
- `{name:-default}` falls back to `default` when the user did not supply a value for `name`.
- Fail-closed: a placeholder with no capture and no default denies the command.
  A raw `{placeholder}` is never passed to the binary.
- User-typed tokens pass through verbatim; only config-sourced strings are substituted.

---

## Profiles

Profiles extend the base config for specific users.
A user matching multiple profiles is an error, and duplicate users across profiles are rejected by `validate`.

```toml
[profiles.admin]
users = ["root", "alice"]

[profiles.admin.global]
help_text = "Admin commands: systemctl, journalctl"

[[profiles.admin.rules]]
action = { type = "run", binary = "/usr/bin/journalctl", args = [], timeout = "5s" }

[[profiles.admin.rules.subcommands]]
name = "-n"
args = ["{int}"]
```

Merge rules for profiles:

- `global`: field-wise override; unspecified fields inherit base.
- `contracts` / `flag_groups`: map merge; profile keys override same-name base keys.
- `rules`: appended after base rules.
- `roots` / `units`: appended, unique, base-first order.

---

## Using `add-rule` to scaffold rules

Instead of hand-writing rules, you can add them with the CLI:

```sh
ssh-guard add-rule --config /etc/ssh_guard/config.toml \
  --cmd "systemctl status sshd"
```

To add to a profile:

```sh
ssh-guard add-rule --config /etc/ssh_guard/config.toml \
  --profile admin --cmd "journalctl -n 10"
```

The `add-rule` subcommand parses the command, finds or creates the rule for the binary, and merges the subcommands/flags.
It writes the updated config back to the same file.

Its worth noting that this subcommand does a best effort merge, and may not always produce the most optimal config.
It is recommended to review the config after using this command.

---

## Generated help

Instead of hand-writing `help_text`, you can render a usage listing derived from the rules:

```sh
ssh-guard help --config /etc/ssh_guard/config.toml
```

Options:

| Flag | Description |
|------|-------------|
| `--profile <name>` | Render the base config merged with that profile's rules. |
| `--tree` | Render subcommands as an indented tree instead of inline. |
| `--verbose` | Enrich template labels with contract details (e.g. `<port:1024-65535>`). |
| `--colour <auto\|always\|never>` | Colourise output. Default `auto` (on for a TTY, off when piped; honours `NO_COLOR`). |

`show_help` rules are skipped. `read_file` / `tail_file` / `stat_path` / `list_dir` rules are shown, since they are allowed inputs.
