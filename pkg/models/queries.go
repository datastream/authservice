package models

import "github.com/datastream/authservice/pkg/db"

var querier *db.Queries

// SetQueries sets the database queries used by model functions.
// Call this once during service initialization.
func SetQueries(q *db.Queries) {
	querier = q
}
