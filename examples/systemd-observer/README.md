# Systemd observer example

## What it covers

Small read-only profile for service inspection:

- `systemctl status <unit>`
- `systemctl show <unit>`
- `journalctl -u <unit> [-n <lines>]`
- `help`

## Why this example exists

This is smallest realistic service-debugging template. It shows:

- enum contracts for fixed unit list
- reusable flag groups
- `show_help` rule
- moderate command surface without file access

## Account expectations

Expected account access:

- permission to run `systemctl` read-only commands
- permission to read journal entries for listed units
- on many distros, journal access means root or membership in `systemd-journal`

If you need more units, extend `[contracts.unit]` rather than opening `systemctl` broadly.
