package main

import (
	"flag"
	"fmt"
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
		claims, err := auth.Claims(ctx.Writer, ctx.Request)
		if err != nil {
			logrus.Error(err)
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}

		email := claims.Email()
		id := claims.Id()

		ctx.JSON(http.StatusOK, fmt.Sprintf("user[%v] %s accessed protected route", id, email))
	})

	hamr.ServeHttp(":8080", router)
}
