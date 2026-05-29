package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/datastream/authservice/pkg/controllers"
	"github.com/datastream/authservice/pkg/core"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-session/redis/v3"
	"github.com/go-session/session/v3"
)

var (
	confFile      = flag.String("c", "config.json", "security service config file")
	version       = flag.Bool("version", false, "print version")
	VersionString = "unset"
)

func main() {
	flag.Parse()
	srv, err := core.LoadConfig(*confFile)
	if err != nil {
		log.Fatalf("LoadConfig err: %v", err)
	}
	// Print version and exit if requested
	if *version {
		printVersion()
		return
	}
	srv.InitDB()
	err = srv.InitOAuthServer()
	if err != nil {
		log.Fatalf("InitOAuthServer err: %v", err)
	}
	// Logger setup
	f, err := os.OpenFile(srv.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("failed to open log file")
	}
	defer f.Close()
	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization", "Accept"},
		AllowOrigins:     srv.Origins,
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	svc := r.Group("/")
	svc.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})
	if srv.Redis != "" {
		session.InitManager(
			session.SetCookieName(srv.SessionName),
			// todo if you want use redis cluster, use redis.NewRedisClusterStore
			session.SetStore(redis.NewRedisStore(&redis.Options{
				Addr:     srv.Redis,
				Password: srv.RedisPassword,
				DB:       srv.RedisDB,
			})),
		)
	}

	r.Static("/static", "./static")

	// SPA-facing APIs (JSON only)
	r.POST("/api/login", controllers.LoginAPI)
	r.POST("/api/signup", controllers.SignupAPI)
	r.POST("/api/logout", controllers.LogoutAPI)
	r.GET("/api/me", controllers.MeAPI)

	r.GET("/api/tokens", controllers.TokensList)
	r.POST("/api/tokens", controllers.ClientTokensCreate)
	r.GET("/api/tokens/redirectUris", controllers.TokenRedirectURIs)
	r.DELETE("/api/tokens/:id", controllers.TokenRevoke)

	// OAuth 2.0 endpoints (unchanged — for external clients)
	r.GET("/logout", controllers.Logout)
	r.GET("/.well-known/openid-configuration", controllers.Config)

	oauth := controllers.NewOAuthController(srv.Server)
	r.GET("/oauth/authorize", controllers.AuthPage)
	r.POST("/oauth/authorize", oauth.OAuthHandler)
	r.POST("/oauth/authorize/approve", oauth.AuthorizeApprove)
	r.POST("/login", oauth.Login)
	r.POST("/oauth/token", oauth.TokenHandler)
	r.GET("/userinfo", oauth.Userinfo)
	r.GET("/userinfo/emails", oauth.UserinfoEmails)
	r.GET("/test", oauth.TestHandler)
	r.POST("/oauth/revoke", oauth.RevokeToken)

	// OpenFGA endpoints (optional - requires FGA API token in config)
	fgaCtrl, err := controllers.NewFGAController(srv.OpenFgaConfig)
	if err != nil {
		log.Fatalf("Failed to initialize FGA controller: %v", err)
	}
	if fgaCtrl != nil {
		authorized := r.Group("/api/v1")
		authorized.Use(controllers.AuthMiddleware())
		authorized.Use(fgaCtrl.FGAMiddleware())
		authorized.POST("/fga/models", fgaCtrl.Models)
		authorized.GET("/fga/models/:id", fgaCtrl.GetModel)

		modelauth := r.Group("/api/v1")
		modelauth.Use(fgaCtrl.FGASepMiddleware())
		modelauth.POST("/fga/models/:id/evaluate", fgaCtrl.Evaluate)
		modelauth.POST("/fga/models/:id/tuples", fgaCtrl.Tuples)
		modelauth.DELETE("/fga/models/:id/tuples", fgaCtrl.DeleteTuples)
	}

	// SPA catch-all: serve index.html for unmatched GET routes.
	// OPTIONS requests get CORS headers so mobile apps can preflight.
	r.NoRoute(func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			for _, origin := range srv.Origins {
				c.Header("Access-Control-Allow-Origin", origin)
			}
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Length, Content-Type, Authorization, Accept")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		if c.Request.Method != http.MethodGet {
			c.Next()
			return
		}
		c.File("./static/index.html")
	})

	r.Run(srv.ListenAddress)
}

// printVersion
func printVersion() {
	info, _ := debug.ReadBuildInfo()
	for _, bInfo := range info.Settings {
		if bInfo.Key == "vcs.revision" {
			fmt.Println("Version:", bInfo.Value)
		}
	}
}
