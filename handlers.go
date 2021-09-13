package hamr

import (
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/hamr/external"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"
)

// registerRequest http API model
type registerRequest struct {
	email    string
	password string
}

// loginRequest http API model
type loginRequest struct {
	email    string
	password string
}

// registerHandler maps to register route
func (auth *auth) registerHandler(ctx *gin.Context) {
	var req *registerRequest
	if err := ctx.ShouldBind(&req); err != nil {
		logrus.Error("registration failed, invalid data: ", err)
		ctx.JSON(http.StatusUnprocessableEntity, "registration failed, invalid data")
		return
	}

	user, err := auth.service.registerUser(&User{
		Username: req.email,
		Email:    req.email,
		Password: req.password,
	})
	if err != nil {
		logrus.Error("registration failed, internal error: ", err)
		ctx.JSON(http.StatusBadRequest, "registration failed, internal error")
		return
	}

	ctx.JSON(http.StatusOK, user)
}

// loginHandler maps to local (email + pwd) login route
func (auth *auth) loginHandler(ctx *gin.Context) {
	var req *loginRequest
	if err := ctx.ShouldBind(&req); err != nil {
		logrus.Error("login failed, invalid data: ", err)
		ctx.JSON(http.StatusUnprocessableEntity, "login failed, invalid data")
		return
	}

	tokens, err := auth.service.authenticate(req.email, req.password)
	if err != nil {
		logrus.Error("login failed, internal error: ", err)
		ctx.JSON(http.StatusBadRequest, "login failed, internal error")
		return
	}

	ctx.JSON(http.StatusOK, tokens)
}

// logoutHandler maps to logout route
func (auth *auth) logoutHandler(ctx *gin.Context) {
	accessToken, _ := getAccessTokenFromRequest(ctx)

	logoutRequest := map[string]string{}
	if err := ctx.ShouldBindJSON(&logoutRequest); err != nil {
		logrus.Error("logout failed, invalid data: ", err)
		ctx.JSON(http.StatusUnprocessableEntity, "logout failed, invalid data")
		return
	}

	refreshToken, ok := logoutRequest["refresh_token"]
	if !ok || strings.TrimSpace(refreshToken) == "" {
		logrus.Error("logout failed, missing refresh_token")
		ctx.JSON(http.StatusBadRequest, "logout failed, missing refresh_token")
		return
	}

	if err := auth.service.destroyAuthenticationSession(accessToken, refreshToken); err != nil {
		logrus.Error("logout failed, internal error: ", err)
		ctx.JSON(http.StatusBadRequest, "logout failed, internal error")
		return
	}
}

// refreshTokenHandler maps to refresh token route
func (auth *auth) refreshTokenHandler(ctx *gin.Context) {
	refreshTokenRequest := map[string]string{}
	if err := ctx.ShouldBindJSON(&refreshTokenRequest); err != nil {
		logrus.Error("refresh token failed, invalid data: ", err)
		ctx.JSON(http.StatusUnprocessableEntity, "refresh token failed, invalid data")
		return
	}
	accessToken := refreshTokenRequest["access_token"]
	refreshToken := refreshTokenRequest["refresh_token"]

	tokens, err := auth.service.refreshToken(accessToken, refreshToken)
	if err != nil {
		logrus.Error("refresh token failed, internal error: ", err)
		ctx.JSON(http.StatusBadRequest, "refresh token failed, internal error")
		return
	}

	ctx.JSON(http.StatusOK, tokens)
}

// externalLoginHandler maps to :provider login route. Redirects to :provider oAuth login url
func (auth *auth) externalLoginHandler(ctx *gin.Context) {
	provider := ctx.Param("provider")

	authenticator, err := external.NewAuthenticator(
		provider,
		auth.config.Scheme,
		auth.config.Host,
		auth.config.Port,
		auth.config.RouteGroup,
		ctx)
	if err != nil {
		logrus.Error("external login redirect failed, internal error: ", err)
		ctx.JSON(http.StatusBadRequest, "external login redirect failed, internal error")
		return
	}

	authenticator.RedirectToLoginUrl()
}

// externalLoginCallbackHandler maps to :provider login callback route. After login :provider redirects to this route
func (auth *auth) externalLoginCallbackHandler(ctx *gin.Context) {
	provider := ctx.Param("provider")

	authenticator, err := external.NewAuthenticator(
		provider,
		auth.config.Scheme,
		auth.config.Host,
		auth.config.Port,
		auth.config.RouteGroup,
		ctx)
	if err != nil {
		logrus.Error("external login callback failed, internal error: ", err)
		ctx.JSON(http.StatusBadRequest, "external login callback failed, internal error")
		return
	}

	claims, err := authenticator.GetExternalProviderClaims()
	if err != nil {
		logrus.Error("external login callback failed, internal error: ", err)
		ctx.JSON(http.StatusBadRequest, "external login callback failed, internal error")
		return
	}

	tokens, err := auth.service.authenticateExternal(claims, provider)
	if err != nil {
		logrus.Error("external login callback failed, internal error: ", err)
		ctx.JSON(http.StatusBadRequest, "external login callback failed, internal error")
		return
	}

	ctx.JSON(http.StatusOK, tokens)
}
