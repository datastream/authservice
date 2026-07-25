package models

import (
	"database/sql"
	"errors"

	"github.com/datastream/authservice/pkg/db"
)

var (
	// ErrDBNotInitialized is returned when model functions are called before
	// InitDB() has been run (querier is nil). This is a startup bug, not a
	// runtime failure — the handler should return 500.
	ErrDBNotInitialized = errors.New("database queries not initialized")
	// ErrDBConnection is returned when a query fails because the database
	// is unreachable (deadline exceeded, connection reset). The handler
	// should return 500.
	ErrDBConnection = errors.New("database connection failed")
)

var querier *db.Queries

// SetQueries sets the database queries used by model functions.
// Call this once during service initialization.
func SetQueries(q *db.Queries) {
	querier = q
}

// IsDBError reports whether err is a real database connection error (not a
// business-status error like sql.ErrNoRows or ErrDBNotInitialized). Call
// this from handlers to decide between 500 (server unhealthy) and a
// business-status code (e.g. 401 for wrong password, 409 for duplicate).
func IsDBError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrDBNotInitialized) {
		return false
	}
	return true
}