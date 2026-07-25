package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"time"
)

//go:embed schema/*.sql
var schemaFS embed.FS

// migrateSchema maps dialect names to embedded schema file paths.
var migrateSchema = map[string]string{
	"postgresql": "schema/schema_postgres.sql",
	"mysql":      "schema/schema_mysql.sql",
	"sqlite":     "schema/schema_sqlite.sql",
}

// Migrate creates tables using the schema file matching the given dialect
// ("postgresql", "mysql", or "sqlite"). Returns an error for unknown dialects.
func Migrate(dbConn *sql.DB, dialect string) error {
	schemaPath, ok := migrateSchema[dialect]
	if !ok {
		return fmt.Errorf("unknown dialect %q", dialect)
	}
	schema, err := schemaFS.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("read schema %q: %w", dialect, err)
	}
	if _, err := dbConn.ExecContext(context.Background(), string(schema)); err != nil {
		return fmt.Errorf("migrate (%s): create tables: %w", dialect, err)
	}
	return nil
}

// ToNullString converts *string to sql.NullString.
func ToNullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: *s, Valid: true}
}

// NullStringToString converts sql.NullString to *string.
func NullStringToString(ns sql.NullString) *string {
	if ns.Valid {
		s := ns.String
		return &s
	}
	return nil
}

// ToNullTime converts *time.Time to sql.NullTime.
func ToNullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{Valid: false}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// NullTimeToTimePtr converts sql.NullTime to *time.Time.
func NullTimeToTimePtr(nt sql.NullTime) *time.Time {
	if nt.Valid {
		t := nt.Time
		return &t
	}
	return nil
}

// InterfaceToString converts a sqlc-generated interface{} (or bare string) to string.
func InterfaceToString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// InterfaceToInt64 converts a sqlc-generated interface{} (or int64) to int64.
func InterfaceToInt64(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int32:
		return int64(n)
	case nil:
		return 0
	}
	return 0
}

// Int64ToBool converts a sqlc-generated int64 to bool.
func Int64ToBool(v interface{}) bool {
	switch n := v.(type) {
	case int64:
		return n != 0
	case int32:
		return n != 0
	}
	return false
}

// BoolToInt32 converts Go bool to int32 for sqlc-generated code.
func BoolToInt32(b bool) int32 {
	if b {
		return 1
	}
	return 0
}
