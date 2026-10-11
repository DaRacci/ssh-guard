# Proxmox host diagnostics example

## What it covers

Read-only host inspection for common Proxmox troubleshooting flows:

- `systemctl` service state and unit metadata
- `journalctl` host and unit logs
- storage and filesystem checks via `df`, `du`, `lsblk`, `zpool`, `smartctl`
- network and process inspection via `ip`, `ss`, `ps`
- host facts via `uname`, `hostname`, `lscpu`, `uptime`, `vmstat`, `dmesg`
- bounded file access under `/var/log`, `/etc`, `/proc`, and `/sys`
- light Proxmox container inspection via `pct config` and `pct list`

## Why this example exists

This is broadest example in repo. It exercises:

- many `run` rules
- file actions: `read_file`, `tail_file`, `stat_path`, `list_dir`
- named captures for file actions
- contracts and inline flag templates
- profile-specific help text
- reused flag groups

## Account expectations

Use dedicated SSH account with read-only intent.

Expected access usually means:

- membership in group that can read systemd journal, commonly `systemd-journal`
- read access to paths under configured `roots`
- permission to run `pct`, `smartctl`, and `zpool` read-only on target host

Some Proxmox installs still require root for parts of this surface. Treat this file as starting point, then trim or adjust per host policy.

## Notes

- `root_set` uses built-in `roots` set supported by current ssh-guard.
- File-oriented commands use named captures so validation catches drift.
- Paths assume Debian/Proxmox-style layout; adjust binary paths for non-default installs.
