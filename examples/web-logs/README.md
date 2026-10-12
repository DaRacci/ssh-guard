# Web logs example

## What it covers

Read-only inspection for nginx and app logs:

- `ls`, `stat`, `cat`, `tail` against bounded paths
- `releases` listing scoped to a named `app` root set
- `journalctl -u nginx [-n <lines>]`
- profile-specific extra roots for deploy user

## Why this example exists

This one focuses on file actions and root-bounded access:

- `read_file`, `tail_file`, `stat_path`, `list_dir`
- named path captures required by current validator
- `lines_capture` for bounded tails
- default `roots` set plus a named `app` root set via `[root_sets]`
- profile root extension with `[profiles.deploy]`

## Account expectations

Expected account access:

- read access to nginx logs, app logs, and nginx config files
- journal access for `nginx.service` by adding the deploy user to systemd-journal
- deploy profile should map only to user that already has read access to release/config paths
