package hamr

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"net/http"
)

/*
Refresh token module.
*/

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

	tokens, err := auth.refreshToken(refreshToken)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())
		return
	}

	ctx.JSON(http.StatusOK, tokens)
}

// refreshToken will generate new pair of access and refresh tokens. Remove old access and refresh tokens from cache
func (auth *auth) refreshToken(refreshToken string) (authTokens, error) {
	// get old refresh token uuid so it can be deleted from cache
	refreshTokenClaims, valid := auth.extractRefreshTokenClaims(refreshToken)
	if !valid {
		return nil, errors.New("invalid refresh_token")
	}

	refreshTokenUuid := refreshTokenClaims["uuid"]
	refreshTokenUserId := refreshTokenClaims["sub"]
	refreshTokenUserEmail := refreshTokenClaims["email"]
	if refreshTokenUuid == nil || refreshTokenUserId == nil || refreshTokenUserEmail == nil {
		return nil, errors.New("invalid claims from refresh_token")
	}

	refreshTokenCached, err := auth.getTokenFromCache(refreshTokenUuid.(string))
	if err != nil {
		logrus.Error("failed to get refresh token from cache: ", err)
		return nil, errors.New("refresh token failed")
	}

	accessTokenUuid, ok := refreshTokenCached["access_token_uuid"]
	if !ok {
		return nil, errors.New("access_token_uuid not found in cached refresh_token")
	}

	// safe to delete both access and refresh tokens from cache, though access token is probably already deleted

	// delete refresh token uuid
	if err = auth.config.CacheStorage.Delete(refreshTokenUuid.(string), accessTokenUuid.(string)); err != nil {
		logrus.Errorf(
			"failed to delete tokens from cache, access token uuid: %s, refresh token uuid: %s",
			accessTokenUuid.(string),
			refreshTokenUuid.(string))
		return nil, errors.New("refresh token failed")
	}

	// generate new access token and refresh token
	claims := generateAuthClaims(refreshTokenUserId.(uint), refreshTokenUserEmail.(string))

	tokens, err := auth.createSession(claims)
	if err != nil {
		logrus.Errorf("refresh token failed to create new token pairs: %v", err)
		return nil, errors.New("refresh token failed")
	}

	return tokens, nil
}
