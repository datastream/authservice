// Package core provides the central AuthService struct that holds configuration,
// database connection, Redis client, OpenFGA client, and OAuth2 server.
package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

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
	Server        *server.Server
	// JWKS fields (RFC 7517)
	PrivateKey   *rsa.PrivateKey
	PublicKey    *rsa.PublicKey
	KeyID        string
	JwksKeyFile  string `yaml:"jwksKeyFile"`
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
	// For SQLite, fall back to dbFile as databaseURI when not set.
	// This lets the existing config work out of the box.
	if a.DatabaseType == "sqlite" && a.DatabaseURI == "" {
		a.DatabaseURI = a.DBFile
	}

	var dbConn *sql.DB
	var err error
	switch a.DatabaseType {
	case "postgresql":
		dbConn, err = sql.Open("pgx", a.DatabaseURI)
	case "mysql":
		dbConn, err = sql.Open("mysql", a.DatabaseURI)
	case "sqlite":
		dbConn, err = sql.Open("sqlite", a.DatabaseURI)
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

	if err := dbConn.Ping(); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	// Create tables from dialect-specific embedded schema.
	if err := db.Migrate(dbConn, a.DatabaseType); err != nil {
		return fmt.Errorf("migrate (%s): %w", a.DatabaseType, err)
	}

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

	a.Server.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		status, ok := errors.StatusCodes[err]
		if !ok {
			status = 400
		}
		return errors.NewResponse(err, status)
	})
	a.Server.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})
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

// deriveKeyID returns a base64url(SHA-256(pubkeyDER)) key identifier
// per RFC 7517 Section 4.5.
func deriveKeyID(pubKey *rsa.PublicKey) string {
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Sprintf("%x", pubKey.N.Bytes())
	}
	hash := sha256.Sum256(derBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// encodeBase64URLInt returns base64url encoding (no padding) of a big integer.
func encodeBase64URLInt(v *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(v.Bytes())
}

// LoadKeyFromFile reads a PEM file containing an RSA private key
// (PKCS#1 or PKCS#8 format) and returns the parsed private key.
func LoadKeyFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("key file contains no PEM block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#1 private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key in PEM file is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

// InitJWKS generates or loads an RSA-2048 key pair for JWKS support.
// If a key file is configured (JwksKeyFile), the key is loaded from file.
// Otherwise a new key pair is generated.
func (a *AuthService) InitJWKS() {
	if a.JwksKeyFile != "" {
		privKey, err := LoadKeyFromFile(a.JwksKeyFile)
		if err != nil {
			log.Fatalf("InitJWKS: failed to load key file %q: %v", a.JwksKeyFile, err)
		}
		a.PrivateKey = privKey
		a.PublicKey = &privKey.PublicKey
		a.KeyID = deriveKeyID(&privKey.PublicKey)
		log.Println("InitJWKS: loaded RSA key from", a.JwksKeyFile)
		return
	}

	// Generate a new RSA-2048 key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("InitJWKS: failed to generate RSA key: %v", err)
	}
	a.PrivateKey = privKey
	a.PublicKey = &privKey.PublicKey
	a.KeyID = deriveKeyID(&privKey.PublicKey)
	log.Println("InitJWKS: generated new RSA-2048 key pair")
}
