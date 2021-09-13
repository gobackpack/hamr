package hamr

import (
	"flag"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/hamr/external"
	"github.com/gobackpack/hamr/internal/cache"
	"github.com/gobackpack/hamr/internal/httpserver"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gorm.io/gorm"
	"sync"
	"time"
)

var Path = flag.String("cpath", "config/", "configuration path")

// auth main api
type auth struct {
	config *Config
	*service
}

// Config for *auth api
type Config struct {
	Scheme           string
	Host             string
	Port             string
	RouteGroup       string
	Router           *gin.Engine
	Db               *gorm.DB
	CacheStorage     cache.Storage
	EnableLocalLogin bool

	adapter *gormadapter.Adapter
	locker  sync.Mutex
}

// New will initialize *auth api
func New(config *Config) *auth {
	adapter, err := gormadapter.NewAdapterByDB(config.Db)
	if err != nil {
		logrus.Fatal("failed to initialize casbin adapter: ", err)
	}

	config.adapter = adapter

	hamrAuth := &auth{
		config: config,
		service: &service{
			accessTokenSecret:  []byte(viper.GetString("auth.access_token.secret")),
			accessTokenExpiry:  time.Minute * time.Duration(viper.GetInt("auth.access_token.expiry")),
			refreshTokenSecret: []byte(viper.GetString("auth.refresh_token.secret")),
			refreshTokenExpiry: time.Minute * time.Duration(viper.GetInt("auth.refresh_token.expiry")),
			db:                 config.Db,
			cache:              config.CacheStorage,
			casbinAdapter:      adapter,
		},
	}

	hamrAuth.initializeRoutes()
	hamrAuth.runMigrations()

	return hamrAuth
}

// NewRouter will return new gin router
func NewRouter() *gin.Engine {
	router := gin.New()

	router.Use(cors.Default())
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	return router
}

// ServeHttp will start http server
func ServeHttp(addr string, router *gin.Engine) {
	httpserver.ServeHttp(addr, router)
}

func InitializeViper() {
	viper.AddConfigPath(*Path)
	viper.SetConfigName("app")
	viper.AutomaticEnv()
	viper.SetConfigType("yml")

	if err := viper.ReadInConfig(); err != nil {
		logrus.Fatal("viper failed to read config file: ", err)
	}
}

func (auth *auth) RegisterProvider(name string, provider external.Provider) {
	auth.config.locker.Lock()
	external.SupportedProviders[name] = provider
	auth.config.locker.Unlock()
}

// AuthorizeRequest is middleware to protect endpoints
func (auth *auth) AuthorizeRequest(obj string, act string, adapter *gormadapter.Adapter) gin.HandlerFunc {
	return auth.service.authorize(obj, act, adapter)
}

// CasbinAdapter will return initialized Casbin adapter. Required for protection with Casbin policies
func (auth *auth) CasbinAdapter() *gormadapter.Adapter {
	return auth.service.casbinAdapter
}

// Router will return router assigned on *auth initialization
func (auth *auth) Router() *gin.Engine {
	return auth.config.Router
}

// initializeRoutes will map all auth routes with respective handlers
func (auth *auth) initializeRoutes() {
	r := auth.config.Router.Group(auth.config.RouteGroup)

	if auth.config.EnableLocalLogin {
		r.POST("register", auth.registerHandler)
		r.POST("login", auth.loginHandler)
	}

	r.POST("logout", auth.AuthorizeRequest("", "", nil), auth.logoutHandler)
	r.POST("token/refresh", auth.refreshTokenHandler)

	r.GET(":provider/login", auth.externalLoginHandler)
	r.GET(":provider/callback", auth.externalLoginCallbackHandler)
}

// runMigrations will automatically run migrations from /migrations/
func (auth *auth) runMigrations() {
	err := auth.config.Db.AutoMigrate(&User{})
	if err != nil {
		logrus.Fatal("migrations failed: ", err)
	}
}
