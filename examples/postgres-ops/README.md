# PostgreSQL operations example

## What it covers

Read-only DB health checks:

- `systemctl status postgresql`
- `journalctl -u postgresql [-n <lines>]`
- `pg_isready`
- fixed `pg-activity`, `pg-db-size`, `pg-replication`, and `pg-settings` query entry points backed by `psql`

## Why this example exists

This example shows how to wrap a powerful tool (`psql`) in fixed, non-shell SQL entry points:

- separate routing commands instead of arbitrary SQL
- `psql` invoked with fixed query text only
- profile-specific extra rule for DBA users
- mix of service, journal, and DB-native probes

## Account expectations

Expected account access:

- permission to connect to PostgreSQL locally
- DB role with read-only monitoring rights, often `pg_monitor` or `pg_read_all_stats`
- journal access for `postgresql.service` if journal rule kept

If database names should be restricted, replace `[contracts.database]` with enum contract of allowed DB names.
