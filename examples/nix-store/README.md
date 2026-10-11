# Nix store diagnostics example

## What it covers

Read-only Nix and NixOS inspection:

- `nix path-info`
- `nix-store --query ...`
- `journalctl -u nix-daemon [-n <lines>]`
- bounded `ls`, `cat`, `tail` on Nix logs and config

## Why this example exists

This example covers mixed command and file workflows on Nix hosts:

- non-standard binary paths common on NixOS
- store-path contract and bounded line counts
- file actions rooted under `/nix` and `/etc/nix`
- profile root extension for builder-oriented accounts

## Account expectations

Expected account access:

- permission to run `nix` and `nix-store` read-only subcommands
- journal access for `nix-daemon.service` if journal rule kept
- read access to `/nix/var/log/nix`, `/etc/nix`, and optional profile paths

Binary paths here assume NixOS-style locations. Adjust for standalone Nix on other distros.
