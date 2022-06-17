package main

import (
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/hamr"
	"github.com/gobackpack/hamr/example/app1/provider"
	"github.com/gobackpack/hamr/oauth/providers"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"net/http"
	"strconv"
	"time"
)

// User with additional fields to match our requirements.
// All these additional fields are ignored during registration/login process!
// You have to additionally populate/update these fields - using auth.PostRegisterCallback for example
type User struct {
	hamr.User
	BirthDate   time.Time
	Age         int
	PhoneNumber int
}

func main() {
	flag.Parse()

	hamr.InitializeViper()

	db, err := hamr.PostgresDb(viper.GetString("database.connstring"))
	if err != nil {
		logrus.Fatal(err)
	}

	conf := hamr.NewConfig(db)
	conf.EnableLocalLogin = true
	auth := hamr.New(conf)

	accountConfirmation := hamr.NewAccountConfirmation(
		"smtp.gmail.com",
		587,
		"",
		"",
		true)

	// optional
	accountConfirmation.Subject = "Confirm Account"
	accountConfirmation.Body = "Confirm clicking on the link: "
	accountConfirmation.LinkText = "Here"

	router := hamr.NewGinRouter()
	auth.MapAuthRoutesGin(router)
	auth.MapAccountConfirmationRoutesGin(router, accountConfirmation)

	// can be used to update other user fields during registration flow
	auth.PostRegisterCallback = func(user *hamr.User, requestData map[string]interface{}) error {
		logrus.Info("requestData: ", requestData)
		/*
			post request body
			{
			    "email": "myemail@gmail.com",
			    "password": "test123",
			    "age": 30,
			    "phone_number": 123456
			}
		*/

		age, _ := strconv.Atoi(fmt.Sprint(requestData["age"]))
		phone, _ := strconv.Atoi(fmt.Sprint(requestData["phone_number"]))

		// update registered user with other fields
		u := &User{}
		u.User = *user
		u.Age = age
		u.BirthDate = time.Now()
		u.PhoneNumber = phone

		if result := db.Save(u); result.Error != nil {
			return result.Error
		}

		return nil
	}

	if err = db.AutoMigrate(&User{}); err != nil {
		logrus.Fatal(err)
	}

	// register oauth providers
	auth.RegisterProvider("github", provider.NewCustomGithub(
		viper.GetString("auth.provider.google.client_id"),
		viper.GetString("auth.provider.google.client_secret")))

	auth.RegisterProvider("google", providers.NewGoogle(
		viper.GetString("auth.provider.google.client_id"),
		viper.GetString("auth.provider.google.client_secret")))

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

	// example #2: protected with roles/policy
	router.GET("protected/policy", auth.AuthorizeGinRequest("usr", "read", auth.CasbinAdapter()), func(ctx *gin.Context) {
		claims, err := auth.Claims(ctx.Writer, ctx.Request)
		if err != nil {
			logrus.Error(err)
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}

		email := claims.Email()
		id := claims.Id()

		ctx.JSON(http.StatusOK, fmt.Sprintf("user[%v] %s accessed policy protected route", id, email))
	})

	// example #3: public
	router.GET("users", func(ctx *gin.Context) {
		var users []*User

		if result := db.Find(&users); result.Error != nil {
			ctx.JSON(http.StatusBadRequest, "failed to fetch users")
			return
		}

		ctx.JSON(http.StatusOK, users)
	})

	hamr.ServeHttp(":8080", router)
}
