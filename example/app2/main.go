package main

import (
	"flag"
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/hamr"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"net/http"
)

func main() {
	flag.Parse()

	hamr.InitializeViper()

	db, err := hamr.PostgresDb(viper.GetString("database.connstring"))
	if err != nil {
		logrus.Fatal(err)
	}

	conf := hamr.NewConfig(db)
	auth := hamr.New(conf)

	router := hamr.NewGinRouter()
	auth.MapAuthRoutesGin(router)

	// example #1: protected without roles/policy
	router.GET("protected", auth.AuthorizeGinRequest("", "", nil), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, "protected")
	})

	// example #2: protected with roles/policy
	router.GET("protected/policy", auth.AuthorizeGinRequest("user", "read", auth.CasbinAdapter()), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, "policy protected")
	})

	hamr.ServeHttp(":8080", router)
}
