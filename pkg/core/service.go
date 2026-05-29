// Package core provides the central AuthService struct that holds configuration,
// database connection, Redis client, OpenFGA client, and OAuth2 server.
// It is responsible for loading configuration, initializing the database, and
// wiring the OAuth2 server with token and client stores.
package core

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/datastream/authservice/pkg/models"
	"github.com/glebarez/sqlite"
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
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// currentClientID tracks the client being authorized for per-client redirect URI validation.
// Set via SetCurrentClientID before HandleAuthorizeRequest, cleared after.
var (
	currentClientID string
	currentClientMu sync.RWMutex
)

// SetCurrentClientID sets the client ID for the current authorization request.
func SetCurrentClientID(id string) {
	currentClientMu.Lock()
	currentClientID = id
	currentClientMu.Unlock()
}

// ClearCurrentClientID clears the current client after authorization flow completes.
func ClearCurrentClientID() {
	currentClientMu.Lock()
	currentClientID = ""
	currentClientMu.Unlock()
}

type AuthService struct {
	ListenAddress string `yaml:"listenAddress"`
	Domain        string `yaml:"domain"`
	DBFile        string `yaml:"dbFile"`
	LogFile       string `yaml:"logFile"`
	DatabaseURI   string `yaml:"databaseURI"`
	DatabaseType  string `yaml:"databaseType"`
	DB            *gorm.DB
	Redis         string `yaml:"redis"`
	RedisPassword string `yaml:"redisPassword"`
	RedisDB       int    `yaml:"redisDB"`
	RedisTokenDB  int    `yaml:"redisTokenDB"`
	// cookie ID
	SessionName string   `yaml:"sessionName"`
	Origins     []string `yaml:"origins"`
	// OpenFGA
	OpenFgaConfig `yaml:"openFgaConfig"`
	// oauth2 server
	Server *server.Server
}
type OpenFgaConfig struct {
	URL     string `yaml:"url"`
	StoreID string `yaml:"storeID"`
	ModelID string `yaml:"modelID"` //model for authorization
	Token   string `yaml:"token"`
}

// read from config.yaml
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

// init database
func (a *AuthService) InitDB() error {
	// config database
	var db *gorm.DB
	var err error
	switch a.DatabaseType {
	case "postgresql":
		db, err = gorm.Open(postgres.Open(a.DatabaseURI), &gorm.Config{})
	case "mysql":
		db, err = gorm.Open(mysql.Open(a.DatabaseURI), &gorm.Config{})
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(a.DatabaseURI), &gorm.Config{})
	default:
		return fmt.Errorf("bad database type: %s", a.DatabaseType)
	}
	models.Register(db)
	a.DB = db
	return err
}

// init manager and server
func (a *AuthService) InitOAuthServer() error {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store, if you want to use redis, just replace it with redis store
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
	// client store
	clientStore := &models.ClientStore{}
	manager.MapClientStorage(clientStore)

	// Override default domain-suffix matching with exact redirect URI validation.
	// Validates against registered redirect URIs for the client, falling back
	// to domain-based host comparison for backward compatibility.
	manager.SetValidateURIHandler(a.validateURI)

	srvConfig := server.NewConfig()
	srvConfig.ForcePKCE = true
	srv := server.NewServer(srvConfig, manager)

	a.Server = srv
	a.SetServerHandlers()
	return nil
}

// set srver handlers
func (a *AuthService) SetServerHandlers() {
	// Accept both Basic Auth and form body for client credentials
	a.Server.SetClientInfoHandler(func(r *http.Request) (string, string, error) {
		// Try Basic Auth first (more secure — secrets not in request body/logs)
		if clientID, secret, ok := r.BasicAuth(); ok {
			return clientID, secret, nil
		}
		// Fall back to form body (backward compatibility)
		return server.ClientFormHandler(r)
	})

	// Restrict to authorization code grant only (not implicit flow)
	a.Server.SetAllowedResponseType(oauth2.Code)

	a.Server.SetUserAuthorizationHandler(userAuthorizeHandler)
	a.Server.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	a.Server.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})
}

// validateURI validates redirect URI against registered URIs for the authorized client.
// When SetCurrentClientID is set (AuthorizerApprove flow), only that client's URIs are checked.
// Otherwise, validates against any client registered for the base host domain.
func (a *AuthService) validateURI(baseURI, redirectURI string) error {
	base, err := url.Parse(baseURI)
	if err != nil {
		return errors.ErrInvalidRedirectURI
	}
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		return errors.ErrInvalidRedirectURI
	}

	// If a client ID is set (AuthorizerApprove programmatic flow), check only that client
	currentClientMu.RLock()
	clientID := currentClientID
	currentClientMu.RUnlock()

	if clientID != "" {
		var token models.Token
		if result := models.DB.Where("client_id = ?", clientID).First(&token); result.Error != nil {
			return errors.ErrInvalidRedirectURI
		}
		if token.RedirectURIs != "" {
			registered := strings.Split(token.RedirectURIs, ";")
			for _, uri := range registered {
				if strings.TrimSpace(uri) == redirectURI {
					return nil
				}
			}
		}
		// No registered URIs for this client — fall through to host comparison
	}

	// Fallback: check if any client for this host has this redirect URI registered
	var clients []models.Token
	if base.Host != "" {
		clients, err = models.FindTokensByDomain(base.Host)
	} else {
		clients, err = models.FindTokensByDisplayDomain(baseURI)
	}
	if err != nil {
		return errors.ErrInvalidRedirectURI
	}
	for _, c := range clients {
		if c.RedirectURIs == "" {
			continue
		}
		registered := strings.Split(c.RedirectURIs, ";")
		for _, uri := range registered {
			if strings.TrimSpace(uri) == redirectURI {
				return nil
			}
		}
	}

	// Final fallback: domain-based host comparison for backward compatibility
	if redirect.Host != base.Host {
		return errors.ErrInvalidRedirectURI
	}
	return nil
}

// user authorizeHandler
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
