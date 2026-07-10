// Package core provides the central AuthService struct that holds configuration,
// database connection, Redis client, OpenFGA client, and OAuth2 server.
package core

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/datastream/authservice/pkg/db"
	"github.com/datastream/authservice/pkg/models"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	oredis "github.com/go-oauth2/redis/v4"
	"github.com/go-redis/redis/v8"
	"github.com/go-session/session/v3"
	"gopkg.in/yaml.v3"
)

type AuthService struct {
	ListenAddress string `yaml:"listenAddress"`
	Domain        string `yaml:"domain"`
	DBFile        string `yaml:"dbFile"`
	LogFile       string `yaml:"logFile"`
	DatabaseURI   string `yaml:"databaseURI"`
	DatabaseType  string `yaml:"databaseType"`
	DB            *sql.DB
	DBQueries     *db.Queries
	Redis         string `yaml:"redis"`
	RedisPassword string `yaml:"redisPassword"`
	RedisDB       int    `yaml:"redisDB"`
	RedisTokenDB  int    `yaml:"redisTokenDB"`
	SessionName   string `yaml:"sessionName"`
	Origins       []string `yaml:"origins"`
	OpenFgaConfig        OpenFgaConfig `yaml:"openFgaConfig"`
	FGAAdminUsers        []string      `yaml:"fgaAdminUsers"`
	Server *server.Server
}

type OpenFgaConfig struct {
	URL     string `yaml:"url"`
	StoreID string `yaml:"storeID"`
	ModelID string `yaml:"modelID"`
	Token   string `yaml:"token"`
}

func LoadConfig(name string) (*AuthService, error) {
	config, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var conf AuthService
	err = yaml.Unmarshal(config, &conf)
	if err != nil {
		return nil, err
	}
	if conf.RedisTokenDB == 0 {
		conf.RedisTokenDB = 1
	}
	return &conf, nil
}

func (a *AuthService) InitDB() error {
	var dbConn *sql.DB
	var err error
	switch a.DatabaseType {
	case "postgresql":
		dbConn, err = sql.Open("pgx", a.DatabaseURI)
		if err == nil {
			err = dbConn.Ping()
		}
	case "mysql":
		dbConn, err = sql.Open("mysql", a.DatabaseURI)
		if err == nil {
			err = dbConn.Ping()
		}
	case "sqlite":
		dbConn, err = sql.Open("sqlite", a.DatabaseURI)
		if err == nil {
			err = dbConn.Ping()
		}
	default:
		return fmt.Errorf("bad database type: %s", a.DatabaseType)
	}
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	dbConn.SetMaxOpenConns(25)
	dbConn.SetMaxIdleConns(10)
	dbConn.SetConnMaxLifetime(5 * time.Minute)

	a.DB = dbConn
	a.DBQueries = db.New(dbConn)
	models.SetQueries(a.DBQueries)
	return nil
}

func (a *AuthService) InitOAuthServer() error {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	if a.Redis == "" {
		manager.MustTokenStorage(store.NewFileTokenStore(a.DBFile))
	} else {
		manager.MapTokenStorage(oredis.NewRedisStore(&redis.Options{
			Addr:     a.Redis,
			Password: a.RedisPassword,
			DB:       a.RedisTokenDB,
		}))
	}

	manager.MapAccessGenerate(generates.NewAccessGenerate())
	clientStore := &db.ClientStore{Queries: a.DBQueries}
	manager.MapClientStorage(clientStore)

	manager.SetValidateURIHandler(a.validateURI)

	srvConfig := server.NewConfig()
	srvConfig.ForcePKCE = true
	srv := server.NewServer(srvConfig, manager)

	a.Server = srv
	a.SetServerHandlers()
	return nil
}

func (a *AuthService) SetServerHandlers() {
	a.Server.SetClientInfoHandler(func(r *http.Request) (string, string, error) {
		if clientID, secret, ok := r.BasicAuth(); ok {
			return clientID, secret, nil
		}
		return server.ClientFormHandler(r)
	})

	a.Server.SetAllowedResponseType(oauth2.Code)
	a.Server.SetUserAuthorizationHandler(userAuthorizeHandler)

	// Password grant — reuse the same username/password check as the
	// login handler so existing users can authenticate via OAuth.
	a.Server.SetPasswordAuthorizationHandler(passwordAuthorizationHandler)
	a.Server.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})
	a.Server.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})
}

// passwordAuthorizationHandler looks up a user by credentials and returns the username.
func passwordAuthorizationHandler(_ context.Context, _ string, username, password string) (userID string, err error) {
	u, lookupErr := models.FindUserByUsername(username)
	if lookupErr != nil || u.CheckPassword(password) != nil {
		log.Println("[password-grant] Invalid credentials for:", username, lookupErr)
		return "", errors.ErrAccessDenied
	}
	return username, nil
}

func (a *AuthService) validateURI(baseURI, redirectURI string) error {
	base, err := url.Parse(baseURI)
	if err != nil {
		return errors.ErrInvalidRedirectURI
	}
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		return errors.ErrInvalidRedirectURI
	}

	clientID := base.Query().Get("client_id")
	if clientID != "" {
		token, err := a.DBQueries.GetTokenByClientID(context.Background(), clientID)
		if err != nil {
			return errors.ErrInvalidRedirectURI
		}
		if token.RedirectUris.Valid && token.RedirectUris.String != "" {
			registered := strings.Split(token.RedirectUris.String, ";")
			for _, uri := range registered {
				if strings.TrimSpace(uri) == redirectURI {
					return nil
				}
			}
		}
	}

	var clients []db.Token
	if base.Host != "" {
		clients, err = a.DBQueries.GetTokensByDomain(context.Background(), base.Host)
	} else {
		clients, err = a.DBQueries.GetTokensByDomain(context.Background(), baseURI)
	}
	if err != nil {
		return errors.ErrInvalidRedirectURI
	}
	for _, c := range clients {
		if c.RedirectUris.Valid && c.RedirectUris.String != "" {
			registered := strings.Split(c.RedirectUris.String, ";")
			for _, uri := range registered {
				if strings.TrimSpace(uri) == redirectURI {
					return nil
				}
			}
		}
	}

	if redirect.Host != base.Host {
		return errors.ErrInvalidRedirectURI
	}
	return nil
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		return
	}
	uid, ok := store.Get("LoggedInUserID")
	if !ok {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}
	userID = uid.(string)
	return
}
