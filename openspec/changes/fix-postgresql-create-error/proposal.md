## Why

The `db.Migrate()` function always executes an SQLite-specific schema file (`AUTOINCREMENT` syntax) against the connected database regardless of whether it is PostgreSQL, MySQL, or SQLite. When users configure a PostgreSQL database the service crashes at startup with `ERROR: syntax error at or near "AUTOINCREMENT"`.

## What Changes

- Extend `db.Migrate()` to accept a `dialect` parameter identifying the target database type
- Add database-specific schema files for PostgreSQL and MySQL alongside the existing SQLite schema
- Route `Migrate()` to the correct schema file based on the configured `DatabaseType`
- Update `InitDB()` in `core/service.go` to pass `DatabaseType` into `Migrate()`

## Capabilities

### New Capabilities
- `multi-db-schema` — database-aware schema migration supporting PostgreSQL, MySQL, and SQLite

### Modified Capabilities
<!-- None — this is an implementation fix, not a spec-level behavior change -->

## Impact

- `pkg/db/helpers.go` — `Migrate()` signature and implementation
- `pkg/core/service.go` — `InitDB()` passes dialect to `Migrate()`
- `pkg/db/schema/` — new `schema_postgres.sql` and `schema_mysql.sql` files
- `sqlc.yaml` — no change (only used for query generation, not migration)