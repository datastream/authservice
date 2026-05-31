package testutils

import (
    "bytes"
    "database/sql"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/gin-gonic/gin"
    "github.com/datastream/authservice/pkg/core"
    "github.com/datastream/authservice/pkg/controllers"
    "github.com/datastream/authservice/pkg/db"
    "github.com/datastream/authservice/pkg/models"
)

// LoadTestService loads the AuthService using the test config and initializes DB and OAuth server.
func LoadTestService(t *testing.T) (*core.AuthService, *gin.Engine) {
    t.Helper()
    cfgPath := "../../cmd/oauthservice/config_test.yaml"
    svc, err := core.LoadConfig(cfgPath)
    if err != nil {
        t.Fatalf("failed to load config: %v", err)
    }
    if err := svc.InitDB(); err != nil {
        t.Fatalf("failed to init DB: %v", err)
    }
    if err := svc.InitOAuthServer(); err != nil {
        t.Fatalf("failed to init OAuth server: %v", err)
    }
    // Build router – replicate the same setup as main.go
    r := gin.Default()
    // CORS setup (copy from main)
    r.Use(gin.Logger())
    r.Use(gin.Recovery())

    // Simple health endpoint
    r.GET("/healthz", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    // Session store – same as main
    if svc.Redis != "" {
        // Redis store is already configured in main; omit for tests
    }

    // Register routes – import controllers package
    // NOTE: this requires the controllers package to be importable
    // We'll set up the same routes as in main.go
    // The import path may need to be adjusted based on module name
    // Using a closure to avoid import cycles
    // This is a simplified version; for full coverage the actual handlers are used.
    //
    // The controllers package is "github.com/datastream/authservice/pkg/controllers"
    //
    // For brevity we only register a subset needed for tests.
    // Additional routes can be added as needed.
    // Register routes – using the same setup as main.go
    r.GET("/login", controllers.LoginPage)
    r.GET("/logout", controllers.Logout)
    r.GET("/api/tokens", controllers.TokensList)
    r.POST("/api/tokens", controllers.ClientTokensCreate)
    r.DELETE("/api/tokens/:id", controllers.TokenRevoke)
    r.GET("/.well-known/openid-configuration", controllers.Config)
    // SPA APIs
    r.POST("/api/login", controllers.LoginAPI)
    r.POST("/api/signup", controllers.SignupAPI)
    r.POST("/api/logout", controllers.LogoutAPI)
    r.GET("/api/me", controllers.MeAPI)
    // OAuth routes
    oauth := controllers.NewOAuthController(svc.Server)
    r.GET("/oauth/authorize", controllers.AuthPage)
    r.POST("/oauth/authorize", oauth.OAuthHandler)
    r.POST("/login", oauth.Login)
    r.POST("/oauth/token", oauth.TokenHandler)
    r.GET("/userinfo", oauth.Userinfo)
    r.GET("/userinfo/emails", oauth.UserinfoEmails)
    r.GET("/test", oauth.OAuthMiddleware(), oauth.TestHandler)
    r.POST("/oauth/revoke", oauth.RevokeToken)

    return svc, r
}

// PerformRequest is a helper to execute a request against the provided router.
func PerformRequest(r http.Handler, method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
    var reqBody []byte
    if body != nil {
        reqBody, _ = json.Marshal(body)
    }
    req, _ := http.NewRequest(method, path, bytes.NewReader(reqBody))
    for k, v := range headers {
        req.Header.Set(k, v)
    }
    if body != nil {
        req.Header.Set("Content-Type", "application/json")
    }
    w := httptest.NewRecorder()
    r.ServeHTTP(w, req)
    return w
}

// CreateTestUser creates a user directly via sqlc for authentication tests.
func CreateTestUser(t *testing.T, conn *sql.DB, username, password string) {
    t.Helper()
    // Set up the querier for the models package
    models.SetQueries(db.New(conn))
    u := models.NewUser(username, "")
    if err := u.GenHashedPassword(password); err != nil {
        t.Fatalf("failed to set password: %v", err)
    }
    if err := u.Save(); err != nil {
        t.Fatalf("failed to create user: %v", err)
    }
}
