package core

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/datastream/authservice/pkg/models"
	"github.com/glebarez/sqlite"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-session/session/v3"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

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
	// cookie ID
	SessionName string   `yaml:"sessionName"`
	Origins     []string `yaml:"origins"`

	Server *server.Server
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
	manager.MustTokenStorage(store.NewFileTokenStore(a.DBFile))

	manager.MapAccessGenerate(generates.NewAccessGenerate())
	// client store
	clientStore := &models.ClientStore{}
	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)

	a.Server = srv
	a.SetServerHandlers()
	return nil
}

// set srver handlers
func (a *AuthService) SetServerHandlers() {
	a.Server.SetAllowGetAccessRequest(true)
	a.Server.SetClientInfoHandler(server.ClientFormHandler)

	a.Server.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (userID string, err error) {
		// check user password
		user, err := models.FindUserByUsername(username)
		if err != nil || user.CheckPassword(password) != nil {
			log.Println("Invalid credentials for user: ", username, err)
			err = errors.New("invalid username or password")
			return
		}
		userID = user.Username
		return
	})

	a.Server.SetUserAuthorizationHandler(userAuthorizeHandler)

	a.Server.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	a.Server.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})
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
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}

	userID = uid.(string)
	return
}
