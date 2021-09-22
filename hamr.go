package hamr

import (
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/hamr/internal/httpserver"
	"github.com/gobackpack/hamr/oauth"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"strings"
	"time"
)

// New will initialize *auth api
func New(config *Config) *auth {
	config.accessTokenSecret = []byte(viper.GetString("auth.access_token.secret"))
	config.accessTokenExpiry = time.Minute * time.Duration(viper.GetInt("auth.access_token.expiry"))
	config.refreshTokenSecret = []byte(viper.GetString("auth.refresh_token.secret"))
	config.refreshTokenExpiry = time.Minute * time.Duration(viper.GetInt("auth.refresh_token.expiry"))
	config.Host = strings.Trim(config.Host, "/")
	config.RouteGroup = strings.Trim(config.RouteGroup, "/")
	config.basePath = config.Scheme + "://" + config.Host + ":" + config.Port
	config.fullPath = config.basePath + "/" + config.RouteGroup

	adapter, err := gormadapter.NewAdapterByDB(config.Db)
	if err != nil {
		logrus.Fatal("failed to initialize casbin adapter: ", err)
	}

	config.casbinAdapter = adapter

	hamrAuth := &auth{
		config: config,
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

// InitializeViper default settings. Config path, type...
func InitializeViper() {
	viper.AddConfigPath(*Path)
	viper.SetConfigName("app")
	viper.AutomaticEnv()
	viper.SetConfigType("yml")

	if err := viper.ReadInConfig(); err != nil {
		logrus.Fatal("viper failed to read config file: ", err)
	}
}

// RegisterProvider will append oauth.SupportedProviders with passed Provider.
// Name must match settings in /config/app.yml
func (auth *auth) RegisterProvider(name string, provider oauth.Provider) {
	oauth.SupportedProviders[name] = provider
}

// AuthorizeRequest is middleware to protect endpoints
func (auth *auth) AuthorizeRequest(obj string, act string, adapter *gormadapter.Adapter) gin.HandlerFunc {
	return auth.authorize(obj, act, adapter)
}

// CasbinAdapter will return initialized Casbin adapter. Required for protection with Casbin policies
func (auth *auth) CasbinAdapter() *gormadapter.Adapter {
	return auth.config.casbinAdapter
}

// Router will return router assigned on *auth initialization
func (auth *auth) Router() *gin.Engine {
	return auth.config.Router
}

// SetAccountConfirmation api
func (auth *auth) SetAccountConfirmation(accountConfirmation *accountConfirmation) {
	accountConfirmation.fullPath = auth.config.fullPath
	auth.config.accountConfirmation = accountConfirmation

	r := auth.config.Router.Group(auth.config.RouteGroup)
	r.GET("confirm", auth.confirmAccountHandler)
	r.POST("confirm/resend", auth.resendAccountConfirmationEmailHandler)
}

// initializeRoutes will map all auth routes with respective handlers
func (auth *auth) initializeRoutes() {
	r := auth.config.Router.Group(auth.config.RouteGroup)

	r.GET(":provider/login", auth.oauthLoginHandler)
	r.GET(":provider/callback", auth.oauthLoginCallbackHandler)
	r.POST("logout", auth.AuthorizeRequest("", "", nil), auth.logoutHandler)
	r.POST("token/refresh", auth.refreshTokenHandler)

	if auth.config.EnableLocalLogin {
		r.POST("register", auth.registerHandler)
		r.POST("login", auth.loginHandler)
	}
}

// runMigrations will automatically run migrations from /migrations/
func (auth *auth) runMigrations() {
	err := auth.config.Db.AutoMigrate(&User{})
	if err != nil {
		logrus.Fatal("migrations failed: ", err)
	}
}
