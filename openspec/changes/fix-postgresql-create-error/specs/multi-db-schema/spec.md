## ADDED Requirements

### Requirement: Migrate must use database-specific schema

The `db.Migrate()` function MUST select the correct schema file based on the configured database type (dialect) and execute only that schema against the connected database.

Supported dialects: `postgresql`, `mysql`, `sqlite`.

#### Scenario: PostgreSQL schema is used for postgresql dialect
- **WHEN** `InitDB()` is called with `DatabaseType = "postgresql"`
- **THEN** `Migrate()` executes `schema/schema_postgres.sql` against the database

#### Scenario: MySQL schema is used for mysql dialect
- **WHEN** `InitDB()` is called with `DatabaseType = "mysql"`
- **THEN** `Migrate()` executes `schema/schema_mysql.sql` against the database

#### Scenario: SQLite schema is used for sqlite dialect
- **WHEN** `InitDB()` is called with `DatabaseType = "sqlite"`
- **THEN** `Migrate()` executes `schema/schema_sqlite.sql` against the database

#### Scenario: Unknown dialect returns an error
- **WHEN** `Migrate()` receives a dialect it does not recognize
- **THEN** it returns an error and no tables are created

### Requirement: Schema files must use dialect-appropriate syntax

Each schema file MUST use the auto-increment and type syntax appropriate for its target database.

- PostgreSQL: `SERIAL` for auto-incrementing integer primary keys, `TIMESTAMP` for timestamps, standard `VARCHAR(n)`
- MySQL: `AUTO_INCREMENT` (underscore) for auto-incrementing integer primary keys, `DATETIME` or `TIMESTAMP`, standard `VARCHAR(n)`
- SQLite: `INTEGER PRIMARY KEY AUTOINCREMENT`

#### Scenario: PostgreSQL schema creates users table correctly
- **WHEN** `schema/schema_postgres.sql` is executed on a fresh PostgreSQL database
- **THEN** the `users` table is created with a `SERIAL` primary key and no syntax errors

#### Scenario: MySQL schema creates tokens table correctly
- **WHEN** `schema/schema_mysql.sql` is executed on a fresh MySQL database
- **THEN** the `tokens` table is created with `AUTO_INCREMENT` and no syntax errors