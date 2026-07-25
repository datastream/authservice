## Context

`pkg/core/service.go:InitDB()` supports three database backends: PostgreSQL, MySQL, and SQLite. However, `pkg/db/helpers.go:Migrate()` executes a single hardcoded schema file (`pkg/db/schema/schema.sql`) written in SQLite dialect. The schema uses `INTEGER PRIMARY KEY AUTOINCREMENT` and SQLite-specific types (`DATETIME`, `BLOB`, `TEXT(255)`). PostgreSQL rejects `AUTOINCREMENT` with a syntax error; MySQL uses `AUTO_INCREMENT` (with underscore).

## Goals / Non-Goals

**Goals:**
- Route the correct database-specific schema file based on `DatabaseType`
- Support PostgreSQL, MySQL, and SQLite from a single `Migrate()` call site
- Keep the change minimal — no ORM, no migration versioning, no schema diffs

**Non-Goals:**
- Adding GORM tags to models or using GORM AutoMigrate
- Schema versioning / incremental migrations
- Cross-database query compatibility (sqlc remains SQLite-only for query generation)

## Decisions

1. **Separate schema files per dialect** (`schema_postgres.sql`, `schema_mysql.sql`, `schema_sqlite.sql`)
   - Rationale: Each database has different auto-increment syntax (`SERIAL`, `AUTO_INCREMENT`, `AUTOINCREMENT`), different type names, and different index syntax. A single dialect-agnostic SQL file is not feasible.
   - The existing file becomes `schema_sqlite.sql` (renamed for clarity).

2. **Pass `dialect` string into `Migrate()`** — change signature to `Migrate(dbConn *sql.DB, dialect string) error`
   - Rationale: Simple, explicit. The caller (`InitDB`) already knows `DatabaseType`. Alternative (detecting from driver name) would be fragile.

3. **Use `CREATE TABLE IF NOT EXISTS` in all dialects**
   - Already present in the existing schema; preserved for all new files to allow safe re-runs.

## Risks / Trade-offs

| Risk | Mitigation |
|------|-----------|
| Existing PostgreSQL / MySQL users lose data on restart (tables don't exist yet) | `CREATE TABLE IF NOT EXISTS` is idempotent; if tables were created by raw SQL before, they already exist and no error occurs. New installations or empty databases work correctly. |
| Schema drift between dialects over time | The tables are identical across dialects (same column names and constraints). Future changes must be replicated to all three files. This is a process risk, not technical. |
| sqlc only generates for SQLite | sqlc.yaml still targets SQLite for query generation. Queries run against the user's chosen backend via `pgx` / `mysql` drivers — the generated SQL parameters are cross-compatible since they use placeholders, not dialect-specific constructs. |

## Migration Plan

1. Rename `schema/schema.sql` → `schema/schema_sqlite.sql`
2. Create `schema/schema_postgres.sql` and `schema/schema_mysql.sql` with dialect-appropriate syntax
3. Update `Migrate()` signature and routing logic
4. Update `InitDB()` call site
5. Test with all three databases

## Open Questions

- Should `AUTOINCREMENT` in SQLite also include explicit constraints matching the other dialects (e.g., unique indexes that match the `UNIQUE` inline constraint)? The existing SQLite schema already uses `UNIQUE` inline which is standard.