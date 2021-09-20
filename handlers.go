package hamr

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/hamr/oauth"
	"net/http"
)

// loginRequest http API model
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// registerHandler maps to register route
func (auth *auth) registerHandler(ctx *gin.Context) {
	var requestData map[string]interface{}
	if err := ctx.ShouldBind(&requestData); err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	if err := validateRequestData(requestData); err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	user, err := auth.service.registerUser(&User{
		Username: requestData["email"].(string),
		Email:    requestData["email"].(string),
		Password: requestData["password"].(string),
	}, requestData)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())
		return
	}

	ctx.JSON(http.StatusOK, user)
}

// loginHandler maps to local (email + pwd) login route
func (auth *auth) loginHandler(ctx *gin.Context) {
	var req *loginRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	tokens, err := auth.service.authenticate(req.Email, req.Password)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())
		return
	}

	ctx.JSON(http.StatusOK, tokens)
}

// logoutHandler maps to logout route
func (auth *auth) logoutHandler(ctx *gin.Context) {
	_, accessToken := getAccessTokenFromRequest(ctx)

	if err := auth.service.destroyAuthenticationSession(accessToken); err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())
		return
	}
}

// refreshTokenHandler maps to refresh token route
func (auth *auth) refreshTokenHandler(ctx *gin.Context) {
	refreshTokenRequest := map[string]string{}
	if err := ctx.ShouldBindJSON(&refreshTokenRequest); err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	refreshToken, ok := refreshTokenRequest["refresh_token"]
	if !ok {
		ctx.JSON(http.StatusUnprocessableEntity, "refresh token failed, invalid data: missing refresh_token")
		return
	}

	tokens, err := auth.service.refreshToken(refreshToken)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())
		return
	}

	ctx.JSON(http.StatusOK, tokens)
}

// oauthLoginHandler maps to :provider login route. Redirects to :provider oAuth login url
func (auth *auth) oauthLoginHandler(ctx *gin.Context) {
	provider := ctx.Param("provider")

	authenticator, err := oauth.NewAuthenticator(provider, auth.config.fullPath, ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())
		return
	}

	authenticator.RedirectToLoginUrl()
}

// oauthLoginCallbackHandler maps to :provider login callback route. After login :provider redirects to this route
func (auth *auth) oauthLoginCallbackHandler(ctx *gin.Context) {
	provider := ctx.Param("provider")

	authenticator, err := oauth.NewAuthenticator(provider, auth.config.fullPath, ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())
		return
	}

	userInfo, err := authenticator.GetUserInfo()
	if err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())
		return
	}

	tokens, err := auth.service.authenticateWithOAuth(userInfo, provider)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())
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
