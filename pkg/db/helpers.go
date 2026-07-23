package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"time"
)

//go:embed schema/schema.sql
var schemaSQL embed.FS

// Migrate creates tables from the embedded schema file.
func Migrate(dbConn *sql.DB) error {
	schema, err := schemaSQL.ReadFile("schema/schema.sql")
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}
	if _, err := dbConn.ExecContext(context.Background(), string(schema)); err != nil {
		return fmt.Errorf("create tables: %w", err)
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

// InterfaceToString converts a sqlc-generated interface{} to string.
func InterfaceToString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Int64ToBool converts a sqlc-generated int64 to bool.
func Int64ToBool(v interface{}) bool {
	if n, ok := v.(int64); ok {
		return n != 0
	}
	return false
}

// BoolToInt64 converts Go bool to SQLite int64.
func BoolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
