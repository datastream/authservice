package controllers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/datastream/authservice/pkg/core"
	"github.com/datastream/authservice/pkg/controllers"
	"github.com/datastream/authservice/pkg/models"
	"github.com/datastream/authservice/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pgTestConfig builds a temporary YAML config for PostgreSQL integration tests.
// Returns the path to the config file (caller should clean it up) and the port used.
func pgTestConfig(t *testing.T, port int, pgURI string) (configPath string) {
	t.Helper()
	cfg := `
listenAddress: "` + ":%d" + `"
domain: "http://localhost"
logFile: "/tmp/authserver_pg_test.log"
dbFile: "/tmp/test_oauth_tokens_pg"
databaseType: postgresql
databaseURI: "` + pgURI + `"
sessionName: "test_session_pg"
redis: ""
redisPassword: ""
redisDB: 0
origins:
  - "https://da-portal.duckdns.org"
`
	cfg = buildFmt(cfg, port, pgURI)
	tmpConfig := "/tmp/test_pg_config_" + testutils.GenerateRandomString(6) + ".yaml"
	require.NoError(t, os.WriteFile(tmpConfig, []byte(cfg), 0644))
	t.Cleanup(func() { _ = os.Remove(tmpConfig) })
	return tmpConfig
}

func buildFmt(fmtStr string, args ...interface{}) string {
	return fmt.Sprintf(fmtStr, args...)
}

// pgTestService loads an AuthService with a PostgreSQL backend for integration tests.
func pgTestService(t *testing.T, port int, pgURI string) (*core.AuthService, http.Handler) {
	t.Helper()

	cfgPath := pgTestConfig(t, port, pgURI)

	svc, err := core.LoadConfig(cfgPath)
	require.NoError(t, err)
	require.NoError(t, svc.InitDB())
	require.NoError(t, svc.InitOAuthServer())
	svc.InitJWKS()
	controllers.SetJWKSConfig(svc.KeyID, svc.PrivateKey, svc.PublicKey)

	r := gin.New()
	r.Use(gin.Recovery())
	r.GET("/healthz", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	r.POST("/api/login", controllers.LoginAPI)
	r.POST("/api/signup", controllers.SignupAPI)
	r.POST("/api/logout", controllers.LogoutAPI)
	r.GET("/api/me", controllers.MeAPI)

	return svc, r
}

// TestAPISignup_PostgreSQL verifies POST /api/signup with PostgreSQL backend.
// Run with: AUTHSERVER_PG_URI="host=/var/run/postgresql user=xianjie dbname=auth sslmode=disable" go test ./pkg/controllers/ -run TestAPISignup_PostgreSQL -v
func TestAPISignup_PostgreSQL(t *testing.T) {
	pgURI := os.Getenv("AUTHSERVER_PG_URI")
	if pgURI == "" {
		t.Skip("skipping PostgreSQL test — set AUTHSERVER_PG_URI")
	}

	svc, r := pgTestService(t, 9098, pgURI)
	uniqueUser := "pgtest_signup_" + testutils.GenerateRandomString(8)

	// Test successful signup
	resp := testutils.PerformRequest(r, "POST", "/api/signup",
		map[string]interface{}{
			"username": uniqueUser,
			"email":    uniqueUser + "@example.com",
			"password": "password123",
		}, nil)

	assert.Equal(t, http.StatusOK, resp.Code,
		"Signup should succeed with 200 OK, got %d. Body: %s", resp.Code, resp.Body.String())
	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])

	// Verify session cookie is set
	cookie := resp.Header().Get("Set-Cookie")
	require.NotEmpty(t, cookie, "Signup response should include a Set-Cookie header")

	// Verify user exists in the database
	var dbID int32
	var username, email string
	err := svc.DB.QueryRowContext(context.Background(),
		"SELECT id, username, email FROM users WHERE username = $1", uniqueUser).Scan(&dbID, &username, &email)
	require.NoError(t, err, "User should exist in PostgreSQL after successful signup")
	assert.Equal(t, uniqueUser, username)
	assert.Equal(t, uniqueUser+"@example.com", email)
	assert.NotZero(t, dbID, "User ID should be populated from SERIAL sequence")
}

// TestUserSave_PopulatesID verifies user.Save() populates the ID field with PostgreSQL.
// Run with: AUTHSERVER_PG_URI="host=/var/run/postgresql user=xianjie dbname=auth sslmode=disable" go test ./pkg/controllers/ -run TestUserSave_PopulatesID -v
func TestUserSave_PopulatesID(t *testing.T) {
	pgURI := os.Getenv("AUTHSERVER_PG_URI")
	if pgURI == "" {
		t.Skip("skipping PostgreSQL test — set AUTHSERVER_PG_URI")
	}

	svc, _ := pgTestService(t, 9099, pgURI)

	// Create a user directly via models
	u := models.NewUser("pgtest_id_"+testutils.GenerateRandomString(6), "idtest@example.com")
	require.NoError(t, u.GenHashedPassword("password123"))
	assert.Zero(t, u.ID, "User ID should be zero before Save()")

	err := u.Save()
	require.NoError(t, err, "user.Save() should succeed in PostgreSQL")
	assert.NotZero(t, u.ID, "User.ID should be populated after Save()")

	// Verify the ID matches the DB
	var dbID int32
	err = svc.DB.QueryRowContext(context.Background(), "SELECT id FROM users WHERE username = $1", u.Username).Scan(&dbID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, dbID, "User.ID should match the database SERIAL value")
}

// TestUserSave_BcryptHashRoundTrip verifies bcrypt hash is stored and retrieved correctly with PostgreSQL.
// Run with: AUTHSERVER_PG_URI="host=/var/run/postgresql user=xianjie dbname=auth sslmode=disable" go test ./pkg/controllers/ -run TestUserSave_BcryptHashRoundTrip -v
func TestUserSave_BcryptHashRoundTrip(t *testing.T) {
	pgURI := os.Getenv("AUTHSERVER_PG_URI")
	if pgURI == "" {
		t.Skip("skipping PostgreSQL test — set AUTHSERVER_PG_URI")
	}

	svc, _ := pgTestService(t, 9100, pgURI)

	uniqueUser := "pgtest_bcrypt_" + testutils.GenerateRandomString(6)

	// Create a user with a known bcrypt hash
	u := models.NewUser(uniqueUser, "bcrypt@example.com")
	password := "s3cureP@ssw0rd!2026"
	require.NoError(t, u.GenHashedPassword(password))
	originalHash := u.HashedPassword
	require.Len(t, originalHash, 60, "bcrypt hash should be 60 bytes")

	err := u.Save()
	require.NoError(t, err, "user.Save() with bcrypt hash should succeed in PostgreSQL")

	// Retrieve the user from the database
	retrieved, err := models.FindUserByUsername(uniqueUser)
	require.NoError(t, err, "FindUserByUsername should work in PostgreSQL")
	assert.Equal(t, uniqueUser, retrieved.Username)

	// Verify the bcrypt hash round-trips correctly
	err = retrieved.CheckPassword(password)
	require.NoError(t, err, "bcrypt hash should round-trip correctly in PostgreSQL")

	// Verify the stored hash is exactly 60 bytes (no truncation)
	var storedLen int
	err = svc.DB.QueryRowContext(context.Background(),
		"SELECT length(hashed_password) FROM users WHERE username = $1", uniqueUser).Scan(&storedLen)
	require.NoError(t, err)
	assert.Equal(t, 60, storedLen, "stored bcrypt hash length should be 60 bytes, got %d", storedLen)

	// Verify the hash bytes are identical
	assert.Equal(t, originalHash, retrieved.HashedPassword,
		"retrieved hash should be byte-identical to the original")
}