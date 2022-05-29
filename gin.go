package hamr

import (
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"net/http"
)

/*
Framework specific
*/

func NewGinRouter() *gin.Engine {
	router := gin.New()

	router.Use(cors.Default())
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	return router
}

func (auth *auth) MapAccountConfirmationRoutesGin(router *gin.Engine, accountConfirmation *accountConfirmation) {
	accountConfirmation.fullPath = auth.config.fullPath
	auth.config.accountConfirmation = accountConfirmation

	r := router.Group(auth.config.RouteGroup)

	r.Handle(http.MethodGet, "confirm/", func(c *gin.Context) {
		auth.confirmAccountHandler(c.Writer, c.Request)
	})

	r.Handle(http.MethodPost, "confirm/resend", func(c *gin.Context) {
		auth.resendAccountConfirmationEmailHandler(c.Writer, c.Request)
	})
}

func (auth *auth) MapAuthRoutesGin(router *gin.Engine) {
	r := router.Group(auth.config.RouteGroup)

	r.GET(":provider/login", func(c *gin.Context) {
		auth.oauthLoginHandler(c.Param("provider"), c.Writer, c.Request)
	})
	r.GET(":provider/callback", func(c *gin.Context) {
		auth.oauthLoginCallbackHandler(c.Param("provider"), c.Writer, c.Request)
	})
	r.POST("logout", auth.AuthorizeGinRequest("", "", nil), func(c *gin.Context) {
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

func (auth *auth) AuthorizeGinRequest(obj, act string, adapter *gormadapter.Adapter) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if authorized, err := auth.authorize(obj, act, adapter, ctx.Writer, ctx.Request); !authorized || err != nil {
			logrus.Error(err)
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}

		ctx.Next()
	}
}
