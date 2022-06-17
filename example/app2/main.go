package main

import (
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/hamr"
	"github.com/gobackpack/hamr/oauth/providers"
	"github.com/sirupsen/logrus"
	"net/http"
)

func main() {
	flag.Parse()

	db, err := hamr.PostgresDb("host=localhost port=5432 dbname=webapp user=postgres password=postgres sslmode=disable")
	if err != nil {
		logrus.Fatal(err)
	}

	conf := hamr.NewConfig(db, hamr.NewRedisCacheStorage(
		"",
		"6379",
		"",
		1))
	auth := hamr.New(conf)

	router := hamr.NewGinRouter()
	auth.MapAuthRoutesGin(router)

	auth.RegisterProvider("google", providers.NewGoogle(
		"212763908463-e0tpnd2jjaqusrj3svfgcp1m792etivb.apps.googleusercontent.com",
		"SOIHmffrwyTqN0QzDfIuaJqq"))

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
