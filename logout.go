package hamr

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"net/http"
)

// logoutHandler maps to logout route
func (auth *auth) logoutHandler(ctx *gin.Context) {
	_, accessToken := getAccessTokenFromRequest(ctx)

	if err := auth.destroyAuthenticationSession(accessToken); err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())
		return
	}
}

// destroyAuthenticationSession will logout user. Remove access and refresh tokens from cache
func (auth *auth) destroyAuthenticationSession(accessToken string) error {
	accessTokenClaims, valid := auth.extractAccessTokenClaims(accessToken)
	if !valid {
		return errors.New("invalid access_token")
	}

	accessTokenUuid := accessTokenClaims["uuid"]
	if accessTokenUuid == nil {
		return errors.New("invalid claims from access_token")
	}

	accessTokenCached, err := auth.getTokenFromCache(accessTokenUuid.(string))
	if err != nil {
		logrus.Error("failed to get access token from cache: ", err)
		return errors.New("logout failed")
	}

	refreshTokenUuid, ok := accessTokenCached["refresh_token_uuid"]
	if !ok {
		return errors.New("refresh_token_uuid not found in cached access_token")
	}

	if err = auth.config.CacheStorage.Delete(accessTokenUuid.(string), refreshTokenUuid.(string)); err != nil {
		logrus.Errorf(
			"failed to delete tokens from cache, access token uuid: %s, refresh token uuid: %s",
			accessTokenUuid.(string),
			refreshTokenUuid.(string))
		return errors.New("failed to destroy authentication session")
	}

	return nil
}
