package main

import (
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/hamr"
	"github.com/gobackpack/hamr/example/provider"
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

	router := hamr.NewRouter()
	db := hamr.PostgresDb(viper.GetString("database.connstring"))

	auth := hamr.New(&hamr.Config{
		Scheme:     "http",
		Host:       "localhost",
		Port:       "8080",
		RouteGroup: "/api/auth",
		Router:     router,
		Db:         db,
		CacheStorage: hamr.NewRedisCacheStorage(
			viper.GetString("auth.cache.redis.host"),
			viper.GetString("auth.cache.redis.port"),
			viper.GetString("auth.cache.redis.password"),
			viper.GetInt("auth.cache.db")),
		EnableLocalLogin: true,
		AccountConfirmation: hamr.NewAccountConfirmation(
			"smtp.gmail.com",
			587,
			"",
			"",
			true),
	})

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

	if err := db.AutoMigrate(&User{}); err != nil {
		logrus.Fatal("failed to migrate *User: ", err)
	}

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
