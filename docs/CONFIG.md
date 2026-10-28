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
action = { type = "run", binary = "/path/to/systemctl", args = [], timeout = "5s" }
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
| `[contracts]` | Named value constraints used in templates. |
| `[flag_groups]` | Named groups of flags reused across rules/subcommands. |
| `[[rules]]` | Allowed command rules. |
| `roots` | Default allowed filesystem roots (the `roots` root set). |
| `[root_sets]` | Additional named filesystem root sets for file actions. |
| `[profiles.<name>]` | Per-user overrides that extend the base config. |

---

## `[global]` options

| Key | Default | Description |
| -------------------- | ------------------------------ | ----------------------------------------------- |
| `audit_log` | `/var/log/ssh-guard-audit.log` | File all audit events are appended to. |
| `audit_format` | `json` | `json` or `logfmt`. |
| `help_text` | _(empty)_ | Shown when the SSH command is empty or `help`. Generated help is used when empty. |
| `log_tag` | `ssh-guard` | Syslog tag for non-audit logging. |
| `max_read_bytes` | `1048576` | Max bytes a `read_file` action will output. |
| `max_tail_lines` | `5000` | Hard cap on lines for `tail_file`. |
| `default_tail_lines` | `200` | Default lines for `tail_file` when unspecified. |
| `dry_run` | `false` | Report matched commands without executing them. |
| `generated_help` | `true` | Serve generated help (derived from the rules) when `help_text` is empty. |

> **`dry_run` audit shape:** a matched command under `dry_run` writes a single
> `allowed` event with `detail = "dry_run"` and **no** `started` event, because
> the command never runs.
> Anything parsing the log as `started` then `allowed` must tolerate the short
> form.

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
| `flags` | `[]` | Allowed optional flags at this level. |
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

`help` and an empty command are handled automatically by the middleware chain.
They print `global.help_text`.
When it is empty, generated help is printed unless [`generated_help`](#global-options) is disabled.
See the [migration guide](MIGRATING.md) if an older config defined a `show_help` rule.

`timeout` accepts strings like `"5s"`, `"5000ms"`, `"2m"`, `"1.5h"`, or a bare integer in milliseconds.
The Default is set to `5000ms`.

---

## Root sets

File actions are sandboxed to a named list of absolute path prefixes.
The action's `root_set` field selects which set applies.

- The default set is named `roots` and comes from the top-level `roots = [...]` array.
- Additional named sets are defined under `[root_sets]`.
- `roots` is reserved: it always refers to the top-level `roots` field, so
  defining `[root_sets] roots = [...]` is rejected by `validate`.

```toml
roots = ["/var/log/nginx"]                         # default "roots" set

[root_sets]
app = ["/srv/app/releases", "/srv/app/current"]    # named "app" set

[[rules]]
command = "releases"
args = ["{path:string}"]
action = { type = "list_dir", path_capture = "path", root_set = "app" }
```

`root_set` must name a set present in the config, or — for profile rules — in the
merged base + profile config. `ssh-guard validate` rejects unknown names,
including a base rule that references a set defined only inside a profile, since
base rules also apply to users with no matching profile.

A resolved path is canonicalized first (following symlinks), then checked against
the selected set's prefixes, so symlinks and `..` traversal cannot escape the
allowed roots.

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

[contracts.log_path]
type = "path"
root_set = "roots"
```

Contract types:

- `int_range`: integer bounded by `min` / `max`
- `string_len`: string length bounded by `min` / `max`
- `enum`: exact match against listed `values`
- `path`: path constrained to a configured root set

### Path contracts

A `path` contract validates a captured argument against one of the configured root sets during command matching.

Example on a `run` rule:

```toml
roots = ["/var/log/"]

[contracts.log_path]
type = "path"
root_set = "roots"

[[rules]]
command = "grep"
flags = ["-n", "-i"]
args = ["{pattern:string}", "{path:log_path}"]
action = { type = "run", binary = "/usr/bin/grep", args = ["--color=never"], timeout = "10s" }
```

```toml
roots = ["/var/log/nginx"]

[root_sets]
app = ["/srv/app/releases", "/srv/app/current"]

[contracts.log_path]
type = "path"
root_set = "roots"

[contracts.output_path]
type = "path"
root_set = "app"
must_exist = false
```

Rules:

- `root_set` selects the allowed root set, either the top-level `roots` or a named set under `[root_sets]`.
- `must_exist` defaults to `true`.
  - When `must_exist = true`, the path must already exist and will fail validation if it does not.
  - When `must_exist = false`, the path may not exist yet, but it must still be within the allowed root set.

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
args = ["{path:log_path}"]
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
action = { type = "run", binary = "/path/to/du", args = ["-d{depth:-1}"], timeout = "30s" }
command = "du"
args = ["{path}"]
```

Flag pattern rules:

- A `flags` entry like `--path={log_path}` matches both `--path=/var/log/nginx/access.log` and `--path /var/log/nginx/access.log`.
- The same applies to short or DOS-style value flags, for example `-n={lines}` or `/level:{int}`.
- Brace syntax in `flags` and `args` is parsed as a template pattern.

Substitution rules:

- `{name}` resolves from the capture that matched at match time.
- `{name:-default}` falls back to `default` when the user did not supply a value for `name`.
- Fail-closed: a placeholder with no capture and no default denies the command.
  A raw `{placeholder}` is never passed to the binary.
- User-typed tokens pass through verbatim; only config-sourced strings are substituted.

### Escaping braces

Braces are special in `flags` / `args` patterns, `action.args` / `pre_args` placeholders, and `path_capture` / `lines_capture` references.
Escape a brace to use it literally:

- `\{` and `\}` emit a literal `{` and `}` that is never treated as a template.
- `\\` emits a single literal `\`.
- A backslash before any other character is kept verbatim.

For example `flags = ['--format=\{\{.Names\}\}']` matches the literal token `--format={{.Names}}`,
and `path_capture = '\{path}'` is not a reference to a capture named `path`.

In a TOML basic (double-quoted) string, write `\\{` to get the config value `\{`;
a TOML literal (single-quoted) string can hold `\{` directly.

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
action = { type = "run", binary = "/path/to/journalctl", args = [], timeout = "5s" }

[[profiles.admin.rules.subcommands]]
name = "-n"
args = ["{int}"]
```

Merge rules for profiles:

- `global`: field-wise override of any `[global]` key (including `dry_run`); unspecified fields inherit base.
- `contracts` / `flag_groups`: map merge; profile keys override same-name base keys.
- `rules`: appended after base rules.
- `roots`: appended, unique, base-first order.
- `root_sets`: same-name sets merge, paths appended unique, base-first order.
- Profile-only root sets can be used by profile contracts and profile rules, but base rules/contracts must validate against the base config because they also apply when no profile matches.

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

If the command uses a bare binary name like `systemctl`, `add-rule` resolves it against the current host `PATH` and writes that full path into the config.
If you later move that config to another machine, review the generated `binary` paths before relying on it.

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

Generated help now starts with a legend, then a `Value details:` block for placeholders and constrained values:

- the legend identifies commands, subcommands, fixed literals, optional flags, and placeholders
- when colour is disabled or unsupported, optional flags fall back to bracketed forms like `[--since]` and `[-n=<int>]`, while placeholders stay angle-bracketed
- placeholders such as `<unit>` or `<port>` get an explanation line showing enum values, integer ranges, and literal prefixes/suffixes
- a trailing `Allowed roots:` section lists every configured root set that bounds file/path actions. With only the default `roots` set the paths are listed flat; once a named `[root_sets]` entry exists, sets are labelled with the default `roots` first, then named sets alphabetically.
