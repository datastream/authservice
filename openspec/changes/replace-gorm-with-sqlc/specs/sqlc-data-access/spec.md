## ADDED Requirements

### Requirement: All data access uses sqlc-generated code
The system SHALL use sqlc to generate type-safe Go code from hand-written SQL queries. All database operations MUST go through generated query functions. No GORM imports SHALL be present in application code.

#### Scenario: User lookup by username
- **WHEN** `FindUserByUsername` is called with a username string
- **THEN** the system executes a generated SQL query and returns a typed `User` struct or `sql.ErrNoRows`

#### Scenario: Token creation via upsert
- **WHEN** `Token.Save()` is called with a `Token` that has no `ClientID`
- **THEN** the system generates IDs/Secrets, executes a SELECT to check existence, and INSERTs or UPDATEs accordingly

#### Scenario: AccessToken lookup by access key
- **WHEN** `AccessToken.FindByAccessKey` is called with an access key
- **THEN** the system executes a generated SQL query with a unique index lookup and returns the `AccessToken`

### Requirement: Model structs are plain Go types
Model structs in `pkg/db/models.go` MUST be plain Go structs with only `json:` tags. No ORM tags (`gorm:*`), no method receivers that perform DB operations.

#### Scenario: User struct has no ORM tags
- **WHEN** the `User` struct is defined in `pkg/db/models.go`
- **THEN** it contains only `json:` struct tags and no `gorm:` tags

#### Scenario: Token struct has no ORM tags
- **WHEN** the `Token` struct is defined in `pkg/db/models.go`
- **THEN** it contains only `json:` struct tags and no `gorm:` tags

### Requirement: Database initialization uses database/sql
The service initialization in `pkg/core/service.go` MUST use `database/sql.Open` with native dialect drivers. The `AuthService.DB` field MUST be `*sql.DB` instead of `*gorm.DB`.

#### Scenario: PostgreSQL connection
- **WHEN** `DatabaseType` is `postgresql`
- **THEN** the system opens a `*sql.DB` connection using `github.com/jackc/pgx/v5`

#### Scenario: MySQL connection
- **WHEN** `DatabaseType` is `mysql`
- **THEN** the system opens a `*sql.DB` connection using `github.com/go-sql-driver/mysql`

#### Scenario: SQLite connection
- **WHEN** `DatabaseType` is `sqlite`
- **THEN** the system opens a `*sql.DB` connection using `modernc.org/sqlite`

### Requirement: sqlc generation is a documented build step
The project MUST include a `.sqlc.yaml` configuration file and update `CLAUDE.md` with `sqlc generate` as the build step for generating query code.

#### Scenario: sqlc configuration exists
- **WHEN** the project root is listed
- **THEN** a `.sqlc.yaml` file exists with query paths, model paths, and dialect settings

#### Scenario: Build instructions document code generation
- **WHEN** `CLAUDE.md` is read
- **THEN** it includes `sqlc generate` in the development commands section
