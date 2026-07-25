## 1. Prepare schema files

- [x] 1.1 Rename `pkg/db/schema/schema.sql` to `pkg/db/schema/schema_sqlite.sql`
- [x] 1.2 Create `pkg/db/schema/schema_postgres.sql` with PostgreSQL-appropriate syntax (`SERIAL` for auto-increment, `TIMESTAMP` for timestamps, `VARCHAR` for strings)
- [x] 1.3 Create `pkg/db/schema/schema_mysql.sql` with MySQL-appropriate syntax (`AUTO_INCREMENT` for auto-increment, `DATETIME` for timestamps, `VARCHAR` for strings)
- [x] 1.4 Ensure all three schema files create identical logical tables (same column names, constraints, indexes)

## 2. Update Migrate() to route by dialect

- [ ] 2.1 Change `Migrate()` signature from `Migrate(dbConn *sql.DB) error` to `Migrate(dbConn *sql.DB, dialect string) error`
- [ ] 2.2 Add dialect detection logic (postgresql → `schema_postgres.sql`, mysql → `schema_mysql.sql`, sqlite → `schema_sqlite.sql`)
- [ ] 2.3 Return an error for unrecognized dialects

## 3. Update InitDB() call site

- [ ] 3.1 Update the `db.Migrate(dbConn)` call in `pkg/core/service.go` to pass `a.DatabaseType` as the dialect argument
- [ ] 3.2 Update the error message to include the dialect name for easier debugging

## 4. Build and verify

- [x] 4.1 Run `go build ./...` to confirm compilation
- [x] 4.2 Run `go vet ./...` to check for issues