package hamr

import (
	"encoding/json"
	"errors"
	"flag"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/hamr/internal/cache"
	"github.com/gobackpack/jwt"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"net/http"
	"strings"
	"time"
)

/*
Main module.
Responsible for tokens (access, refresh), claims and sessions.
*/

var Path = flag.String("cpath", "config/", "configuration path")

// auth main api
type auth struct {
	config               *Config
	PostRegisterCallback func(user *User, requestData map[string]interface{}) error
}

// Config for *auth api
type Config struct {
	Scheme           string
	Host             string
	Port             string
	RouteGroup       string
	Router           *gin.Engine
	Db               *gorm.DB
	CacheStorage     cache.Storage
	EnableLocalLogin bool

	accessTokenSecret  []byte
	accessTokenExpiry  time.Duration
	refreshTokenSecret []byte
	refreshTokenExpiry time.Duration

	basePath            string
	fullPath            string
	casbinAdapter       *gormadapter.Adapter
	accountConfirmation *accountConfirmation
}

// tokenDetails holds access and refresh token details
type tokenDetails struct {
	accessTokenValue   string
	accessTokenUuid    string
	accessTokenExpiry  time.Duration
	refreshTokenValue  string
	refreshTokenUuid   string
	refreshTokenExpiry time.Duration
}

// tokenClaims contains required claims for authentication (sub + email). Validated in: validateClaims(claims tokenClaims).
// These claims will be generated in access and refresh tokens
type tokenClaims map[string]interface{}

// authTokens contains pair of access_token and refresh_token after authentication. These token pairs are returned to the user
type authTokens map[string]string

// createSession will create *User login session. Generate access and refresh tokens and save both tokens in cache storage
func (auth *auth) createSession(claims tokenClaims) (authTokens, error) {
	if err := validateClaims(claims); err != nil {
		return nil, err
	}

	td, err := auth.generateTokens(claims)
	if err != nil {
		return nil, err
	}

	if err = auth.storeTokensInCache(claims["sub"], td); err != nil {
		return nil, err
	}

	tokens := make(authTokens)
	tokens["access_token"] = td.accessTokenValue
	tokens["refresh_token"] = td.refreshTokenValue

	return tokens, nil
}

// generateTokens will generate pair of access and refresh tokens
func (auth *auth) generateTokens(claims tokenClaims) (*tokenDetails, error) {
	accessTokenUuid, accessTokenValue, err := generateToken(auth.config.accessTokenSecret, auth.config.accessTokenExpiry, claims)
	if err != nil {
		return nil, err
	}

	refreshTokenUuid, refreshTokenValue, err := generateToken(auth.config.refreshTokenSecret, auth.config.refreshTokenExpiry, claims)
	if err != nil {
		return nil, err
	}

	return &tokenDetails{
		accessTokenValue:   accessTokenValue,
		accessTokenUuid:    accessTokenUuid,
		accessTokenExpiry:  auth.config.accessTokenExpiry,
		refreshTokenValue:  refreshTokenValue,
		refreshTokenUuid:   refreshTokenUuid,
		refreshTokenExpiry: auth.config.refreshTokenExpiry,
	}, nil
}

// storeTokensInCache will save access and refresh tokens in cache
func (auth *auth) storeTokensInCache(sub interface{}, td *tokenDetails) error {
	// these properties are created so we can later easily find connection between access and refresh tokens
	// it's needed for easier cleanup on logout and refresh/token

	accessTokenCacheValue := map[string]interface{}{
		"sub":                sub,
		"refresh_token_uuid": td.refreshTokenUuid,
	}
	refreshTokenCacheValue := map[string]interface{}{
		"sub":               sub,
		"access_token_uuid": td.accessTokenUuid,
	}

	return auth.config.CacheStorage.Store(
		&cache.Item{
			Key:        td.accessTokenUuid,
			Value:      accessTokenCacheValue,
			Expiration: td.accessTokenExpiry,
		}, &cache.Item{
			Key:        td.refreshTokenUuid,
			Value:      refreshTokenCacheValue,
			Expiration: td.refreshTokenExpiry,
		})
}

// destroySession will remove access and refresh tokens from cache
func (auth *auth) destroySession(accessToken string) error {
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

// extractAccessTokenClaims will validate and extract access token claims. Access token secret is used for validation
func (auth *auth) extractAccessTokenClaims(accessToken string) (map[string]interface{}, bool) {
	return extractToken(accessToken, auth.config.accessTokenSecret)
}

// extractRefreshTokenClaims will validate and extract refresh token. Refresh token secret is used for validation
func (auth *auth) extractRefreshTokenClaims(refreshToken string) (map[string]interface{}, bool) {
	return extractToken(refreshToken, auth.config.refreshTokenSecret)
}

// getTokenFromCache will get and unmarshal token from cache
func (auth *auth) getTokenFromCache(tokenUuid string) (map[string]interface{}, error) {
	cachedTokenBytes, err := auth.config.CacheStorage.Get(tokenUuid)
	if err != nil {
		return nil, errors.New("token is no longer active")
	}

	var cachedToken map[string]interface{}
	if err = json.Unmarshal(cachedTokenBytes, &cachedToken); err != nil {
		return nil, errors.New("getTokenFromCache unmarshal failed: " + err.Error())
	}

	return cachedToken, nil
}

// validateClaims will check for required *tokenClaims
func validateClaims(claims tokenClaims) error {
	_, ok := claims["sub"]
	if !ok {
		return errors.New("missing sub from claims")
	}

	_, ok = claims["email"]
	if !ok {
		return errors.New("missing email from claims")
	}

	return nil
}

// generateToken is used for both access and refresh token.
// It will generate token value and uuid.
// Can be split into two separate functions if needed (ex. different claims used)
func generateToken(tokenSecret []byte, tokenExpiry time.Duration, claims tokenClaims) (string, string, error) {
	token := &jwt.Token{
		Secret: tokenSecret,
	}

	tClaims := make(map[string]interface{})
	for k, v := range claims {
		tClaims[k] = v
	}
	tUuid := uuid.New().String()
	tClaims["exp"] = jwt.TokenExpiry(tokenExpiry)
	tClaims["uuid"] = tUuid

	tValue, err := token.Generate(tClaims)
	if err != nil {
		return "", "", err
	}

	return tUuid, tValue, nil
}

// extractToken will validate and extract claims from given token
func extractToken(token string, secret []byte) (map[string]interface{}, bool) {
	jwtToken := &jwt.Token{
		Secret: secret,
	}

	return jwtToken.ValidateAndExtract(token)
}

// generateAuthClaims for access token
func generateAuthClaims(sub uint, email string) tokenClaims {
	claims := make(tokenClaims)
	claims["sub"] = sub
	claims["email"] = email

	return claims
}

// getAccessTokenFromRequest will extract access token from request's Authorization headers.
// Returns schema and access_token.
func getAccessTokenFromRequest(ctx *gin.Context) (string, string) {
	authHeader := strings.Split(ctx.GetHeader("Authorization"), " ")
	if len(authHeader) != 2 {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return "", ""
	}

	schema, token := authHeader[0], authHeader[1]
	if schema != "Bearer" {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return "", ""
	}

	return schema, token
}
