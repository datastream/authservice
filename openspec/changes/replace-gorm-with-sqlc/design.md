## Context

The auth service currently uses GORM (`gorm.io/gorm v1.31.0`) as its ORM across 3 model files (`User`, `Token`, `AccessToken`), a global `models.DB *gorm.DB` singleton, and direct GORM method calls in controllers (e.g. `models.DB.Model(&Token{}).Where(...).Update(...)`). The service supports Postgres, MySQL, and SQLite via GORM dialect drivers.

## Goals / Non-Goals

**Goals:**
- Replace all GORM code with sqlc-generated type-safe queries
- Support the same database backends (PostgreSQL, MySQL, SQLite)
- Eliminate reflection-based ORM overhead
- Maintain identical public API (HTTP handlers unchanged)
- Keep the same database schema (zero-downtime migration not needed)

**Non-Goals:**
- Database schema changes or migrations
- Adding new models or fields
- Changing config file format
- Adding connection pooling configuration beyond what drivers provide
- Query performance benchmarking (future work)

## Decisions

### 1. Use `database/sql` + native drivers instead of GORM dialects
- **PostgreSQL**: `github.com/jackc/pgx/v5` (replaces `gorm.io/driver/postgres`)
- **MySQL**: `github.com/go-sql-driver/mysql` (via `database/sql`)
- **SQLite**: `github.com/mattn/go-sqlite3` or `modernc.org/sqlite` (replaces `github.com/glebarez/sqlite`)
- **Rationale**: sqlc generates code for `database/sql` or pgx directly. Using `database/sql` keeps the same cross-dialect flexibility GORM provided.

### 2. sqlc generates for `database/sql` (not pgx raw)
- **Rationale**: `database/sql` interface is needed to support MySQL and SQLite alongside PostgreSQL. pgx-native generation only works with Postgres.

### 3. sqlc config targets all three dialects
- **Rationale**: sqlc supports PostgreSQL, MySQL, and SQLite. We'll use `database/sql` queries which are dialect-portable for our simple queries (SELECT by id, WHERE clauses, INSERT, UPDATE, DELETE).

### 4. Keep `pkg/models/` directory, rewrite content
- Restructure as `pkg/db/` with:
  - `models.go` — plain structs (no GORM tags)
  - `queries/` — `.sql` files per entity
  - `db.go` — generated Go code + `db.Queries` struct wrapper
- **Rationale**: Clean separation between data shapes and data access.

### 5. Replace global `models.DB` singleton with structured dependency injection
- `db.Queries` struct held in `core.AuthService.DB` (replace `*gorm.DB` field)
- **Rationale**: Testability and cleaner architecture.

## Risks / Trade-offs

| Risk | Mitigation |
|------|------------|
| SQLite support via `database/sql` with `modernc.org/sqlite` (pure Go) vs `mattn/go-sqlite3` (CGO) | Use `modernc.org/sqlite` to avoid CGO requirements in CI |
| Some GORM features (AutoMigrate, hooks) have no sqlc equivalent | Hand-write migration init in `InitDB()`; remove Before/After hooks (none are used) |
| `FirstOrCreate` pattern (used in `User.Save()` and `Token.Save()`) is not portable across dialects | Implement as application-level upsert: `SELECT` then `INSERT` or `UPDATE` |
| `redirect_uris` atomic update uses `DB.Model().Where().Update()` — a GORM-specific chain | Replace with plain `UPDATE tokens SET redirect_uris = ? WHERE client_id = ?` |

## Migration Plan

1. Add sqlc CLI as a build tool (in `sqlc.yaml` + `go.mod` as tool dependency)
2. Write plain Go model structs (copy from GORM, strip tags)
3. Write `.sql` files for every GORM method used
4. Generate code with `sqlc generate`
5. Rewrite `pkg/core/service.go` to use `*sql.DB` instead of `*gorm.DB`
6. Rewrite `pkg/models/` to call generated queries
7. Rewrite GORM-specific controller code in `tokens.go`
8. Add `sqlc generate` to build instructions in CLAUDE.md
9. Run `go build` and fix any type errors
10. Verify all endpoints work with each database backend
