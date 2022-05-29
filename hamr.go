package hamr

import (
	"encoding/json"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/hamr/internal/httpserver"
	"github.com/gobackpack/hamr/oauth"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gorm.io/gorm"
	"net/http"
	"strconv"
	"strings"
	"time"
)

/*
Hamr module.
Exposes *auth api, binds it all together.
*/

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
	seedCasbinPolicy(config.Db)

	return hamrAuth
}

func NewConfig(db *gorm.DB) *Config {
	return &Config{
		Scheme:     "http",
		Host:       "localhost",
		Port:       "8080",
		RouteGroup: "/api/auth",
		Db:         db,
		CacheStorage: NewRedisCacheStorage(
			viper.GetString("auth.cache.redis.host"),
			viper.GetString("auth.cache.redis.port"),
			viper.GetString("auth.cache.redis.password"),
			viper.GetInt("auth.cache.db")),
		EnableLocalLogin: true,
	}
}

// ServeHttp will start http server
func ServeHttp(addr string, router http.Handler) {
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

// CasbinAdapter will return initialized Casbin adapter. Required for protection with Casbin policies
func (auth *auth) CasbinAdapter() *gormadapter.Adapter {
	return auth.config.casbinAdapter
}

// JSON response
func JSON(statusCode int, w http.ResponseWriter, data interface{}) {
	resp, err := json.Marshal(data)
	if err != nil {
		logrus.Error(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if _, err = w.Write(resp); err != nil {
		logrus.Error(err)
		return
	}
}

// runMigrations will automatically run migrations, TODO: from /migrations/
func (auth *auth) runMigrations() {
	err := auth.config.Db.AutoMigrate(&User{})
	if err != nil {
		logrus.Fatal("migrations failed: ", err)
	}
}

// getAccessTokenFromRequest will extract access token from request's Authorization headers.
// Returns schema and access_token.
func getAccessTokenFromRequest(w http.ResponseWriter, r *http.Request) (string, string) {
	authHeader := strings.Split(r.Header.Get("Authorization"), " ")
	if len(authHeader) != 2 {
		JSON(http.StatusUnauthorized, w, "")
		return "", ""
	}

	schema, token := authHeader[0], authHeader[1]
	if schema != "Bearer" {
		JSON(http.StatusUnauthorized, w, "")
		return "", ""
	}

	return schema, token
}

/*
Frameworks specific
*/

// NewGinRouter will return new gin router
func NewGinRouter() *gin.Engine {
	router := gin.New()

	router.Use(cors.Default())
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	return router
}

// SetAccountConfirmation api
func (auth *auth) SetAccountConfirmation(accountConfirmation *accountConfirmation) {
	accountConfirmation.fullPath = auth.config.fullPath
	auth.config.accountConfirmation = accountConfirmation

	r := auth.config.Router.Group(auth.config.RouteGroup)

	r.Handle(http.MethodGet, "confirm/", func(c *gin.Context) {
		auth.confirmAccountHandler(c.Writer, c.Request)
	})

	r.Handle(http.MethodPost, "confirm/resend", func(c *gin.Context) {
		auth.resendAccountConfirmationEmailHandler(c.Writer, c.Request)
	})
}

// initializeRoutes will map all auth routes with respective handlers
func (auth *auth) initializeRoutes() {
	r := auth.config.Router.Group(auth.config.RouteGroup)

	r.GET(":provider/login", func(c *gin.Context) {
		auth.oauthLoginHandler(c.Param("provider"), c.Writer, c.Request)
	})
	r.GET(":provider/callback", func(c *gin.Context) {
		auth.oauthLoginCallbackHandler(c.Param("provider"), c.Writer, c.Request)
	})
	r.POST("logout", auth.GinAuthMiddleware("", "", nil), func(c *gin.Context) {
		auth.logoutHandler(c.Writer, c.Request)
	})
	r.POST("token/refresh", func(c *gin.Context) {
		auth.refreshTokenHandler(c.Writer, c.Request)
	})

	if auth.config.EnableLocalLogin {
		r.POST("register", func(c *gin.Context) {
			auth.registerHandler(c.Writer, c.Request)
		})
		r.POST("login", func(c *gin.Context) {
			auth.loginHandler(c.Writer, c.Request)
		})
	}
}

func (auth *auth) GinAuthMiddleware(obj, act string, adapter *gormadapter.Adapter) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		_, token := getAccessTokenFromRequest(ctx.Writer, ctx.Request)
		if strings.TrimSpace(token) == "" {
			logrus.Error("token not found")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, valid := auth.extractAccessTokenClaims(token)
		if claims == nil || !valid {
			logrus.Error("invalid access token claims, valid: ", valid)
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userIdFromRequestClaims := claims["sub"]
		accessTokenUuid := claims["uuid"]
		if userIdFromRequestClaims == nil || accessTokenUuid == nil {
			logrus.Error("userId or accessTokenUuid is nil")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		accessTokenCached, err := auth.getTokenFromCache(accessTokenUuid.(string))
		if err != nil {
			logrus.Error("failed to get access token from cache: ", err)
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userIdFromCacheClaims, ok := accessTokenCached["sub"]
		if !ok {
			logrus.Error("sub not found in accessTokenCached")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if userIdFromRequestClaims.(float64) != userIdFromCacheClaims.(float64) {
			logrus.Error("userIdFromRequestClaims does not match userIdFromCacheClaims")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if adapter != nil {
			id := strconv.Itoa(int(userIdFromRequestClaims.(float64)))

			// enforce Casbin policy
			if policyOk, policyErr := enforce(id, obj, act, adapter); policyErr != nil || !policyOk {
				logrus.Error("casbin policy not passed, err: ", policyErr)
				ctx.AbortWithStatus(http.StatusUnauthorized)
				return
			}
		}

		ctx.Next()
	}
}
