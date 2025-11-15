package main

import (
	"flag"
	"fmt"
	"log"
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
	verison       = flag.Bool("version", false, "print version")
	VersionString = "unset"
)

func main() {
	flag.Parse()
	srv, err := core.LoadConfig(*confFile)
	if err != nil {
		log.Fatalf("LoadConfig err: %v", err)
	}
	// Print version and exit if requested
	if *verison {
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
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type"},
		AllowOrigins:     srv.Origins,
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	svc := r.Group("/")
	svc.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{
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
	// OAuth 2.0 endpoints
	r.GET("/login", controllers.LoginPage)
	r.GET("/logout", controllers.Logout)
	r.GET("/manager", controllers.Managerpage)
	r.GET("/tokens", controllers.TokensList)
	r.POST("/tokens", controllers.ClientTokensCreate)
	r.GET("/signup", controllers.NewUser)
	r.POST("/signup", controllers.Signup)
	r.POST("/authentication", controllers.TokenAuth)

	oauth := controllers.NewOAuthController(srv.Server)
	r.GET("/oauth/authorize", controllers.AuthPage)
	r.POST("/oauth/authorize", oauth.OAuthHandler)
	r.POST("/login", oauth.Login)
	r.POST("/oauth/token", oauth.TokenHandler)
	r.GET("/profile", oauth.Profile)
	r.GET("/profile/emails", oauth.ProfileEmails)
	r.GET("/test", oauth.TestHandler)

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
