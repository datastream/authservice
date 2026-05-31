package db

import (
	"database/sql"
	"time"
)

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
