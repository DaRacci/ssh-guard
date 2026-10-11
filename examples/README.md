# Example configs

Current example set:

- `proxmox`: broad Proxmox host diagnostics
- `systemd-observer`: small unit/journal observer
- `web-logs`: bounded file/log inspection
- `postgres-ops`: DB monitoring with fixed `psql` queries
- `nix-store`: Nix/NixOS store and daemon inspection

Each example directory contains:

- `config.toml`: config template
- `README.md`: scope, capabilities, account expectations

`cargo test` validates these files so examples don't drift on breaking changes.
