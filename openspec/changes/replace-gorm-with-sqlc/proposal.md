## Why

The project uses GORM as its ORM, which adds ~200KB to binary size, introduces reflection-heavy runtime overhead, and obscures the actual SQL being executed. sqlc generates type-safe Go code from hand-written SQL, giving compile-time type safety, zero reflection overhead, and full query transparency — critical for an auth service where correctness and performance matter.

## What Changes

- Remove all GORM imports (`gorm.io/gorm`, `gorm.io/driver/*`)
- Replace GORM models with plain Go structs and hand-written SQL queries in `.sql` files
- Generate Go query functions via sqlc from `.sql` + `.sqlc.yaml` config
- Migrate `pkg/models/` layer from GORM-backed methods to sqlc-generated code
- Update `pkg/core/service.go` DB initialisation to use `database/sql` + driver directly
- Keep the same public API — no changes to HTTP handlers or external contracts

## Capabilities

### New Capabilities
- `sqlc-data-access`: Type-safe data access layer generated from SQL queries using sqlc; replaces GORM models with generated Go code driven by `.sql` files and `.sqlc.yaml` configuration.

### Modified Capabilities
<!-- None — this is purely an implementation detail change with no behavior-level spec changes -->

## Impact

- **Code**: `pkg/models/*.go`, `pkg/core/service.go`, `pkg/controllers/tokens.go` (GORM-specific `DB.Model().Where().Update()` calls)
- **Dependencies**: Remove `gorm.io/*` (3 deps), add `github.com/qdm12/sqlc` (build tool) + `github.com/jackc/pgx/v5` or `github.com/go-sql-driver/mysql` + `github.com/lib/pq` (runtime drivers)
- **Database**: Same schemas — no migration needed. sqlc connects via `database/sql` with the same dialect drivers
- **Build**: Add `sqlc generate` as a build step before `go build`
- **Breaking**: Internal API change only. HTTP API, config format, and database schema remain identical
