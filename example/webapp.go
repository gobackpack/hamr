package main

import (
	"flag"
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/hamr"
	"github.com/gobackpack/hamr/example/provider"
	"github.com/spf13/viper"
	"net/http"
)

func main() {
	flag.Parse()

	hamr.InitializeViper()

	router := hamr.NewRouter()

	auth := hamr.New(&hamr.Config{
		Scheme:     "http",
		Host:       "localhost",
		Port:       "8080",
		RouteGroup: "/api/auth",
		Router:     router,
		Db:         hamr.PostgresDb(viper.GetString("database.connstring")),
		CacheStorage: hamr.NewRedisCacheStorage(
			viper.GetString("auth.cache.redis.host"),
			viper.GetString("auth.cache.redis.port"),
			viper.GetString("auth.cache.redis.password"),
			viper.GetInt("auth.cache.db")),
		EnableLocalLogin: true,
	})

	// register custom provider
	// name property must match value from config/app.yml -> provider.github, provider.google...
	auth.RegisterProvider("github", provider.NewCustomGithub())

	// example #1: protected without roles/policy
	router.GET("protected", auth.AuthorizeRequest("", "", nil), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, "protected")
	})

	// example #2: protected with roles/policy
	router.GET("protected/policy", auth.AuthorizeRequest("usr", "read", auth.CasbinAdapter()), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, "policy protected")
	})

	hamr.ServeHttp(":8080", router)
}
