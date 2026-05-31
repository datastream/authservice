## 1. Setup

- [x] 1.1 Add sqlc dependency and create `.sqlc.yaml` configuration targeting PostgreSQL, MySQL, and SQLite with `database/sql` emissions
- [x] 1.2 Update `go.mod` — add `github.com/jackc/pgx/v5`, `github.com/go-sql-driver/mysql`, `modernc.org/sqlite`; remove `gorm.io/*` (3 deps)

## 2. Define Plain Model Structs

- [x] 2.1 Create `pkg/db/models.go` with plain `User`, `Token`, `AccessToken` structs (no GORM tags, only `json:` and `db:` struct tags)

## 3. Write SQL Query Files

- [x] 3.1 Create `pkg/db/queries/user.sql` — `GetUserByUsername`, `CreateUser` (upsert), `SaveUser` (insert)
- [x] 3.2 Create `pkg/db/queries/token.sql` — `GetTokenByClientID`, `CreateToken` (upsert), `DeleteToken`, `GetTokensByUserID`, `GetTokensByDomain`, `UpdateRedirectURIs` (2 atomic UPDATEs)
- [x] 3.3 Create `pkg/db/queries/accesstoken.sql` — `GetAccessTokenByAccessKey`

## 4. Generate and Wire Code

- [x] 4.1 Run `sqlc generate` and verify generated code compiles
- [x] 4.2 Create `pkg/db/db.go` with `Queries` struct wrapping `*sql.DB` and `New(querierQuerier) *Queries`
- [x] 4.3 Create `pkg/db/query.go` interface alias or wrapper if needed for testability

## 5. Migrate Service Initialization

- [x] 5.1 Replace `*gorm.DB` with `*sql.DB` in `pkg/core/service.go` `AuthService` struct
- [x] 5.2 Rewrite `InitDB()` to use `sql.Open` with the appropriate driver per `DatabaseType`
- [x] 5.3 Replace `models.Register(db)` call with table creation or removal (manual schema matching current GORM tables)

## 6. Migrate Model Layer

- [x] 6.1 Rewrite `pkg/models/user.go` to call `db.Queries.GetUserByUsername` and `CreateUser`
- [x] 6.2 Rewrite `pkg/models/tokens.go` — replace `ClientStore.GetByID`, `FindTokensByUserID`, `FindTokenByClientID`, `FindTokensByDomain`, `FindTokensByDisplayDomain`, `Token.Save`, `Token.Delete`
- [x] 6.3 Rewrite `pkg/models/accesstoken.go` — replace `FindByAccessKey`

## 7. Migrate Controllers

- [x] 7.1 Fix `pkg/controllers/tokens.go` — replace `models.DB.Model(&Token{}).Where(...).Update("redirect_uris", ...)` calls with generated `UpdateRedirectURIs` query
- [x] 7.2 Fix `pkg/core/service.go` `validateURI()` — replace inline `models.DB.Where(...).First(...)` with generated query call

## 8. Cleanup and Verify

- [x] 8.1 Remove all `gorm.io/*` imports from every `.go` file
- [x] 8.2 Add `sqlc generate` to CLAUDE.md build instructions
- [x] 8.3 Run `go build ./...` and fix all compilation errors
- [x] 8.4 Run `go vet ./...` and confirm no issues
