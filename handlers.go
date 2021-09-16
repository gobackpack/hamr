package hamr

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/hamr/oauth"
	"github.com/sirupsen/logrus"
	"net/http"
)

// loginRequest http API model
type loginRequest struct {
	email    string
	password string
}

// registerHandler maps to register route
func (auth *auth) registerHandler(ctx *gin.Context) {
	var requestData map[string]interface{}
	if err := ctx.ShouldBind(&requestData); err != nil {
		logrus.Error("registration failed, invalid data: ", err)
		ctx.JSON(http.StatusUnprocessableEntity, "registration failed, invalid data")
		return
	}

	if err := validateRequestData(requestData); err != nil {
		logrus.Error("registration failed, invalid data: ", err)
		ctx.JSON(http.StatusUnprocessableEntity, "registration failed, invalid data")
		return
	}

	user, err := auth.service.registerUser(&User{
		Username: requestData["email"].(string),
		Email:    requestData["email"].(string),
		Password: requestData["password"].(string),
	}, requestData)
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
	_, accessToken := getAccessTokenFromRequest(ctx)

	if err := auth.service.destroyAuthenticationSession(accessToken); err != nil {
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
	refreshToken, ok := refreshTokenRequest["refresh_token"]
	if !ok {
		logrus.Error("refresh token failed, invalid data: missing refresh_token field")
		ctx.JSON(http.StatusUnprocessableEntity, "refresh token failed, invalid data")
		return
	}

	tokens, err := auth.service.refreshToken(refreshToken)
	if err != nil {
		logrus.Error("refresh token failed, internal error: ", err)
		ctx.JSON(http.StatusBadRequest, "refresh token failed, internal error")
		return
	}

	ctx.JSON(http.StatusOK, tokens)
}

// oauthLoginHandler maps to :provider login route. Redirects to :provider oAuth login url
func (auth *auth) oauthLoginHandler(ctx *gin.Context) {
	provider := ctx.Param("provider")

	authenticator, err := oauth.NewAuthenticator(
		provider,
		auth.config.Scheme,
		auth.config.Host,
		auth.config.Port,
		auth.config.RouteGroup,
		ctx)
	if err != nil {
		logrus.Error("oauth login redirect failed, internal error: ", err)
		ctx.JSON(http.StatusBadRequest, "oauth login redirect failed, internal error")
		return
	}

	authenticator.RedirectToLoginUrl()
}

// oauthLoginCallbackHandler maps to :provider login callback route. After login :provider redirects to this route
func (auth *auth) oauthLoginCallbackHandler(ctx *gin.Context) {
	provider := ctx.Param("provider")

	authenticator, err := oauth.NewAuthenticator(
		provider,
		auth.config.Scheme,
		auth.config.Host,
		auth.config.Port,
		auth.config.RouteGroup,
		ctx)
	if err != nil {
		logrus.Error("oauth login callback failed, internal error: ", err)
		ctx.JSON(http.StatusBadRequest, "oauth login callback failed, internal error")
		return
	}

	userInfo, err := authenticator.GetUserInfo()
	if err != nil {
		logrus.Error("oauth login callback failed, internal error: ", err)
		ctx.JSON(http.StatusBadRequest, "oauth login callback failed, internal error")
		return
	}

	tokens, err := auth.service.authenticateWithOAuth(userInfo, provider)
	if err != nil {
		logrus.Error("oauth login callback failed, internal error: ", err)
		ctx.JSON(http.StatusBadRequest, "oauth login callback failed, internal error")
		return
	}

	ctx.JSON(http.StatusOK, tokens)
}

// validateRequestData will check for required fields for registration flow
func validateRequestData(requestData map[string]interface{}) error {
	_, ok := requestData["email"]
	if !ok {
		return errors.New("missing email property")
	}

	_, ok = requestData["password"]
	if !ok {
		return errors.New("missing password property")
	}

	return nil
}
