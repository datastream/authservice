package db

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Remove test DB before running
	_ = os.Remove("/tmp/test_sql_queries.db")
	os.Exit(m.Run())
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite", "/tmp/test_sql_queries.db")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
		_ = os.Remove("/tmp/test_sql_queries.db")
	})
	require.NoError(t, Migrate(conn, "sqlite"))
	return conn
}

// TestCreateUserAndFindByUsername tests CreateUser and GetUserByUsername queries.
func TestCreateUserAndFindByUsername(t *testing.T) {
	q := Queries{db: openTestDB(t)}

	// Task 6.1: INSERT user with description and SELECT back
	err := q.CreateUser(context.Background(), CreateUserParams{
		Username:       "testuser",
		HashedPassword: []byte("hashed_password"),
		Email:          sql.NullString{String: "test@example.com", Valid: true},
	})
	require.NoError(t, err)

	// SELECT back via query
	found, err := q.GetUserByUsername(context.Background(), "testuser")
	require.NoError(t, err)
	assert.Equal(t, "testuser", found.Username)

	// Verify user exists
	byID, err := q.GetUserByID(context.Background(), found.ID)
	require.NoError(t, err)
	assert.Equal(t, "testuser", byID.Username)
}

// TestCreateTokenAndFindByClientID tests CreateToken and GetTokenByClientID queries.
func TestCreateTokenAndFindByClientID(t *testing.T) {
	q := Queries{db: openTestDB(t)}

	// Task 6.2: INSERT token with description and SELECT back
	err := q.CreateToken(context.Background(), CreateTokenParams{
		UserID:       "user-1",
		ClientID:     "client-abc",
		ClientSecret: "secret-xyz",
		Domain:       "testapp.example.com",
		Public:       1,
		RedirectUris: sql.NullString{String: "http://localhost:3000/callback", Valid: true},
	})
	require.NoError(t, err)

	// SELECT back via query
	found, err := q.GetTokenByClientID(context.Background(), "client-abc")
	require.NoError(t, err)
	assert.Equal(t, "client-abc", found.ClientID)
	assert.Equal(t, "testapp.example.com", found.Domain)
	assert.True(t, Int64ToBool(found.Public))
}

// TestCreateTokenWithDescription verifies description column works in schema and queries.
func TestCreateTokenWithDescription(t *testing.T) {
	q := Queries{db: openTestDB(t)}

	// Insert with description
	err := q.CreateToken(context.Background(), CreateTokenParams{
		UserID:       "user-desc",
		ClientID:     "client-desc",
		ClientSecret: "secret-desc",
		Domain:       "desc.example.com",
		Public:       0,
		Description:  sql.NullString{String: "my OAuth client", Valid: true},
	})
	require.NoError(t, err)

	// Verify description was stored
	found, err := q.GetTokenByClientID(context.Background(), "client-desc")
	require.NoError(t, err)
	assert.True(t, found.Description.Valid)
	assert.Equal(t, "my OAuth client", found.Description.String)
}

// TestTokensWithDescription verifies tokens can have NULL description.
func TestTokensWithNullDescription(t *testing.T) {
	q := Queries{db: openTestDB(t)}

	// Insert without description
	err := q.CreateToken(context.Background(), CreateTokenParams{
		UserID:       "user-nullable",
		ClientID:     "client-null-desc",
		ClientSecret: "secret-null",
		Domain:       "null-desc.example.com",
		Public:       0,
	})
	require.NoError(t, err)

	found, err := q.GetTokenByClientID(context.Background(), "client-null-desc")
	require.NoError(t, err)
	assert.False(t, found.Description.Valid)
}

// TestGetTokensByUserID tests GetTokensByUserID query.
func TestGetTokensByUserID(t *testing.T) {
	q := Queries{db: openTestDB(t)}

	// Insert multiple tokens for same user
	for i := 0; i < 3; i++ {
		clientID := "user-multi-" + string(rune('a'+i))
		err := q.CreateToken(context.Background(), CreateTokenParams{
			UserID:       "user-multi",
			ClientID:     clientID,
			ClientSecret: "secret-" + string(rune('a'+i)),
			Domain:       "multi-" + string(rune('a'+i)) + ".example.com",
			Public:       1,
		})
		require.NoError(t, err)
	}

	tokens, err := q.GetTokensByUserID(context.Background(), "user-multi")
	require.NoError(t, err)
	assert.Len(t, tokens, 3)
}

// TestUpdateRedirectURIs tests the UpdateRedirectURIs query.
func TestUpdateRedirectURIs(t *testing.T) {
	q := Queries{db: openTestDB(t)}

	// Create token first
	err := q.CreateToken(context.Background(), CreateTokenParams{
		UserID:       "user-update",
		ClientID:     "client-update",
		ClientSecret: "secret-update",
		Domain:       "update.example.com",
		Public:       1,
		RedirectUris: sql.NullString{String: "http://old.com/callback", Valid: true},
	})
	require.NoError(t, err)

	// Task 6.4: UPDATE redirect URIs
	err = q.UpdateRedirectURIs(context.Background(), UpdateRedirectURIsParams{
		ClientID:     "client-update",
		RedirectUris: sql.NullString{String: "http://new.com/callback", Valid: true},
	})
	require.NoError(t, err)

	// Verify redirect URIs updated
	found, err := q.GetTokenByClientID(context.Background(), "client-update")
	require.NoError(t, err)
	assert.Equal(t, "http://new.com/callback", found.RedirectUris.String)
}

// TestDeleteToken tests the DeleteToken query.
func TestDeleteToken(t *testing.T) {
	q := Queries{db: openTestDB(t)}

	// Create token first
	err := q.CreateToken(context.Background(), CreateTokenParams{
		UserID:       "user-delete",
		ClientID:     "client-delete",
		ClientSecret: "secret-delete",
		Domain:       "delete.example.com",
		Public:       0,
	})
	require.NoError(t, err)

	// Task 6.5: DELETE token
	err = q.DeleteToken(context.Background(), "client-delete")
	require.NoError(t, err)

	// Verify deleted
	_, err = q.GetTokenByClientID(context.Background(), "client-delete")
	assert.Error(t, err)
}

// TestGetTokensByDomain tests GetTokensByDomain query.
func TestGetTokensByDomain(t *testing.T) {
	q := Queries{db: openTestDB(t)}

	// Insert tokens for same domain
	for i := 0; i < 3; i++ {
		clientID := "domain-same-" + string(rune('a'+i))
		err := q.CreateToken(context.Background(), CreateTokenParams{
			UserID:       "user-domain-" + string(rune('a'+i)),
			ClientID:     clientID,
			ClientSecret: "secret-" + string(rune('a'+i)),
			Domain:       "shared.example.com",
			Public:       1,
		})
		require.NoError(t, err)
	}

	tokens, err := q.GetTokensByDomain(context.Background(), "shared.example.com")
	require.NoError(t, err)
	assert.Len(t, tokens, 3)
}

// TestAccessTokenByAccessKey tests GetAccessTokenByAccessKey query.
func TestAccessTokenByAccessKey(t *testing.T) {
	q := Queries{db: openTestDB(t)}

	// Task 6.3: INSERT access token with description and SELECT back
	_, err := q.db.ExecContext(context.Background(),
		"INSERT INTO access_tokens (user_name, access_key, secret_key, description, created_at, updated_at) VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))",
		"awsuser", "AKIA1234567890", "sk/secret+key==", "AWS HMAC auth token",
	)
	require.NoError(t, err)

	// Find by access key
	found, err := q.GetAccessTokenByAccessKey(context.Background(), "AKIA1234567890")
	require.NoError(t, err)
	assert.Equal(t, "awsuser", found.UserName)
	assert.Equal(t, "AKIA1234567890", found.AccessKey)
	assert.True(t, found.Description.Valid)
	assert.Equal(t, "AWS HMAC auth token", found.Description.String)
}

// TestAccessTokenByAccessKeyAndSecretKey tests the composite key query.
func TestAccessTokenByAccessKeyAndSecretKey(t *testing.T) {
	q := Queries{db: openTestDB(t)}

	_, err := q.db.ExecContext(context.Background(),
		"INSERT INTO access_tokens (user_name, access_key, secret_key, description, created_at, updated_at) VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))",
		"awsuser2", "AKIA0987654321", "sk/other+key==", "Other token",
	)
	require.NoError(t, err)

	// Correct both keys
	found, err := q.GetAccessTokenByAccessKeyAndSecretKey(context.Background(), GetAccessTokenByAccessKeyAndSecretKeyParams{
		AccessKey: "AKIA0987654321",
		SecretKey: "sk/other+key==",
	})
	require.NoError(t, err)
	assert.Equal(t, "awsuser2", found.UserName)

	// Wrong secret key — should not find
	_, err = q.GetAccessTokenByAccessKeyAndSecretKey(context.Background(), GetAccessTokenByAccessKeyAndSecretKeyParams{
		AccessKey: "AKIA0987654321",
		SecretKey: "wrong-secret",
	})
	assert.Error(t, err)
}

// TestDescriptionNotReservedKeyword verifies that the description column
// works correctly — no SQL reserved keyword conflicts in SQLite.
func TestDescriptionNotReservedKeyword(t *testing.T) {
	q := Queries{db: openTestDB(t)}

	// Insert with NULL description (column must accept NULL)
	err := q.CreateToken(context.Background(), CreateTokenParams{
		UserID:       "user-null",
		ClientID:     "client-null",
		ClientSecret: "secret-null",
		Domain:       "null.example.com",
		Public:       0,
	})
	require.NoError(t, err)

	// Insert with non-NULL description
	err = q.CreateToken(context.Background(), CreateTokenParams{
		UserID:       "user-with-desc",
		ClientID:     "client-with-desc",
		ClientSecret: "secret-with-desc",
		Domain:       "with-desc.example.com",
		Public:       1,
		Description:  sql.NullString{String: "has a description", Valid: true},
	})
	require.NoError(t, err)

	// Verify both were inserted
	rows, err := q.db.QueryContext(context.Background(),
		"SELECT COUNT(*) FROM tokens WHERE domain IN ('null.example.com', 'with-desc.example.com')")
	require.NoError(t, err)
	var count int
	require.True(t, rows.Next())
	require.NoError(t, rows.Scan(&count))
	assert.Equal(t, 2, count)
}