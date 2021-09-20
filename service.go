package hamr

import (
	"encoding/json"
	"errors"
	"fmt"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gobackpack/crypto"
	"github.com/gobackpack/hamr/internal/cache"
	"github.com/gobackpack/hamr/oauth/models"
	"github.com/gobackpack/jwt"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"time"
)

// service for authentication. Exposes services for register, login, logout, refreshToken
type service struct {
	accessTokenSecret  []byte
	accessTokenExpiry  time.Duration
	refreshTokenSecret []byte
	refreshTokenExpiry time.Duration

	cache               cache.Storage
	casbinAdapter       *gormadapter.Adapter
	db                  *gorm.DB
	accountConfirmation *accountConfirmation

	PostRegisterCallback func(user *User, requestData map[string]interface{}) error
}

// tokenDetails holds access and refresh token details
type tokenDetails struct {
	accessToken        string
	accessTokenUuid    string
	accessTokenExpiry  time.Duration
	refreshToken       string
	refreshTokenUuid   string
	refreshTokenExpiry time.Duration
}

// tokenClaims contains required claims for authentication (sub + email). Validated in: validateClaims(claims tokenClaims).
// These claims will be generated in access and refresh tokens
type tokenClaims map[string]interface{}

// authTokens contains pair of access_token and refresh_token after authentication. These token pairs are returned to the user
type authTokens map[string]string

// registerUser will save user into database
func (svc *service) registerUser(user *User, requestData map[string]interface{}) (*User, error) {
	existingUser := svc.getUserByEmail(user.Email)
	if existingUser != nil {
		return nil, errors.New("user email is already registered: " + user.Email)
	}

	argon := crypto.NewArgon2()
	argon.Plain = user.Password

	if err := argon.Hash(); err != nil {
		logrus.Errorf("password hash for user %s failed: %v", user.Email, err)
		return nil, errors.New("failed to hash password")
	}

	user.Password = argon.Hashed
	user.LastLogin = nil

	if err := svc.addUser(user); err != nil {
		logrus.Errorf("failed to save user %s in database: %v", user.Email, err)
		return nil, errors.New("failed to save user")
	}

	if svc.PostRegisterCallback != nil {
		if err := svc.PostRegisterCallback(user, requestData); err != nil {
			logrus.Errorf("PostRegisterCallback for user %s failed: %v", user.Email, err)
			return nil, err
		}
	}

	if svc.accountConfirmation != nil {
		go func(user *User) {
			token := uuid.New().String()
			if err := svc.accountConfirmation.sendConfirmationEmail(user.Email, token); err != nil {
				logrus.Errorf("send account confirmation to email %s failed: %v", user.Email, err)
			}

			user.ConfirmationToken = token
			user.ConfirmationTokenExpiry = &svc.accountConfirmation.tokenExpiry

			if err := svc.editUser(user); err != nil {
				logrus.Errorf("update account confirmation for user %s failed: %v", user.Email, err)
			}
		}(user)
	}

	return user, nil
}

// authenticate will use local login (email + pwd) to login user. Validate credentials and save tokens in cache
func (svc *service) authenticate(email, password string) (authTokens, error) {
	user := svc.getUserByEmail(email)
	if user == nil {
		return nil, errors.New(fmt.Sprintf("user email %s not registered", email))
	}

	if svc.accountConfirmation != nil && !user.Confirmed {
		return nil, errors.New("user account not confirmed")
	}

	claims := generateAuthClaims(user.Id, user.Email)
	lastLogin := time.Now().UTC()

	// user previously registered using local register (email + pwd)
	// password exists, validate credentials
	if user.Password != "" && validateCredentials(user, password) {
		user.LastLogin = &lastLogin

		if err := svc.editUser(user); err != nil {
			logrus.Errorf("updating user %s during authentication failed: %v", email, err)
			return nil, errors.New("authentication failed")
		}

		tokens, err := svc.createAuth(claims)
		if err != nil {
			logrus.Errorf("user %s failed to authenticate: %v", email, err)
			return nil, errors.New("authentication failed")
		}

		return tokens, nil
	} else if user.Password == "" && user.ExternalProvider != "" {
		return nil, errors.New(fmt.Sprintf("please login with %s account or set new password from account settings", user.ExternalProvider))
	}

	return nil, errors.New("invalid credentials")
}

// authenticateWithOAuth will login user with oauth provider (google, github...), save tokens in cache
func (svc *service) authenticateWithOAuth(userInfo *models.UserInfo, provider string) (authTokens, error) {
	externalId := userInfo.ExternalId
	email := userInfo.Email

	user := svc.getUserByEmail(email)
	lastLogin := time.Now().UTC()

	if user == nil {
		user = &User{
			Email:            email,
			Username:         email,
			ExternalId:       externalId,
			ExternalProvider: provider,
			LastLogin:        &lastLogin,
		}

		setAccountConfirmed(user)

		if err := svc.addUser(user); err != nil {
			logrus.Errorf("failed to save user %s in database: %v", email, err)
			return nil, errors.New("authentication failed")
		}

		if svc.PostRegisterCallback != nil {
			if err := svc.PostRegisterCallback(user, nil); err != nil {
				logrus.Errorf("PostRegisterCallback for user %s failed: %v", user.Email, err)
				return nil, err
			}
		}
	} else {
		user.ExternalId = externalId
		user.ExternalProvider = provider
		user.LastLogin = &lastLogin

		setAccountConfirmed(user)

		if err := svc.editUser(user); err != nil {
			logrus.Errorf("updating user %s during authentication failed: %v", email, err)
			return nil, errors.New("authentication failed")
		}
	}

	claims := generateAuthClaims(user.Id, user.Email)

	tokens, err := svc.createAuth(claims)
	if err != nil {
		logrus.Errorf("user %s failed to authenticate: %v", email, err)
		return nil, errors.New("authentication failed")
	}

	return tokens, nil
}

// destroyAuthenticationSession will logout user. Remove access and refresh tokens from cache
func (svc *service) destroyAuthenticationSession(accessToken string) error {
	accessTokenClaims, valid := svc.extractAccessTokenClaims(accessToken)
	if !valid {
		return errors.New("invalid access_token")
	}

	accessTokenUuid := accessTokenClaims["uuid"]
	if accessTokenUuid == nil {
		return errors.New("invalid claims from access_token")
	}

	accessTokenCachedBytes, err := svc.cache.Get(accessTokenUuid.(string))
	if err != nil {
		logrus.Errorf("failed to get access token from cache, uuid: %s, token: %s", accessTokenUuid.(string), accessToken)
		return errors.New("failed to destroy authentication session")
	}

	var accessTokenCached map[string]interface{}
	if err = json.Unmarshal(accessTokenCachedBytes, &accessTokenCached); err != nil {
		logrus.Errorf(
			"failed to unmarshal access token from cache, uuid: %s, bytes: %s",
			accessTokenUuid.(string),
			string(accessTokenCachedBytes))
		return errors.New("failed to destroy authentication session")
	}

	refreshTokenUuid, ok := accessTokenCached["refresh_token_uuid"]
	if !ok {
		return errors.New("refresh_token_uuid not found in cached access_token")
	}

	if err = svc.cache.Delete(accessTokenUuid.(string), refreshTokenUuid.(string)); err != nil {
		logrus.Errorf(
			"failed to delete tokens from cache, access token uuid: %s, refresh token uuid: %s",
			accessTokenUuid.(string),
			refreshTokenUuid.(string))
		return errors.New("failed to destroy authentication session")
	}

	return nil
}

// refreshToken will generate new pair of access and refresh tokens. Remove old access and refresh tokens from cache
func (svc *service) refreshToken(refreshToken string) (authTokens, error) {
	// get old refresh token uuid so it can be deleted from cache
	refreshTokenClaims, valid := svc.extractRefreshTokenClaims(refreshToken)
	if !valid {
		return nil, errors.New("invalid refresh_token")
	}

	refreshTokenUuid := refreshTokenClaims["uuid"]
	refreshTokenUserId := refreshTokenClaims["sub"]
	refreshTokenUserEmail := refreshTokenClaims["email"]
	if refreshTokenUuid == nil || refreshTokenUserId == nil || refreshTokenUserEmail == nil {
		return nil, errors.New("invalid claims from refresh_token")
	}

	// make sure refresh token is still active, optional check
	refreshTokenCachedBytes, err := svc.cache.Get(refreshTokenUuid.(string))
	if err != nil {
		return nil, errors.New("refresh_token is no longer active")
	}

	// get old access token uuid so it can be deleted from cache
	// we do not need to validate it - it's already expired, probably does not even exists!
	var refreshTokenCached map[string]interface{}
	if err = json.Unmarshal(refreshTokenCachedBytes, &refreshTokenCached); err != nil {
		logrus.Errorf(
			"failed to unmarshal refresh token from cache, uuid: %s, bytes: %s",
			refreshTokenUuid.(string),
			string(refreshTokenCachedBytes))
		return nil, errors.New("refresh token failed")
	}
	accessTokenUuid, ok := refreshTokenCached["access_token_uuid"]
	if !ok {
		return nil, errors.New("access_token_uuid not found in cached refresh_token")
	}

	// safe to delete both access and refresh tokens from cache, though access token is probably already deleted

	// delete refresh token uuid
	if err = svc.cache.Delete(refreshTokenUuid.(string), accessTokenUuid.(string)); err != nil {
		logrus.Errorf(
			"failed to delete tokens from cache, access token uuid: %s, refresh token uuid: %s",
			accessTokenUuid.(string),
			refreshTokenUuid.(string))
		return nil, errors.New("refresh token failed")
	}

	// generate new access token and refresh token
	claims := generateAuthClaims(refreshTokenUserId.(uint), refreshTokenUserEmail.(string))

	tokens, err := svc.createAuth(claims)
	if err != nil {
		logrus.Errorf("refresh token failed to create new token pairs: %v", err)
		return nil, errors.New("refresh token failed")
	}

	return tokens, nil
}

// createAuth will create *User login session. Generate access and refresh tokens and save both tokens in cache storage
func (svc *service) createAuth(claims tokenClaims) (authTokens, error) {
	if err := validateClaims(claims); err != nil {
		return nil, err
	}

	td, err := svc.generateTokens(claims)
	if err != nil {
		return nil, err
	}

	// these properties are created so we can later easily find connection between access and refresh tokens
	// it's needed for easier cleanup on logout and refresh/token
	accessTokenCacheValue := map[string]interface{}{
		"sub":                claims["sub"],
		"refresh_token_uuid": td.refreshTokenUuid,
	}
	refreshTokenCacheValue := map[string]interface{}{
		"sub":               claims["sub"],
		"access_token_uuid": td.accessTokenUuid,
	}

	if err = svc.cache.Store(
		&cache.Item{
			Key:        td.accessTokenUuid,
			Value:      accessTokenCacheValue,
			Expiration: td.accessTokenExpiry,
		}, &cache.Item{
			Key:        td.refreshTokenUuid,
			Value:      refreshTokenCacheValue,
			Expiration: td.refreshTokenExpiry,
		}); err != nil {
		return nil, err
	}

	tokens := make(authTokens)
	tokens["access_token"] = td.accessToken
	tokens["refresh_token"] = td.refreshToken

	return tokens, nil
}

// generateTokens will generate pair of access and refresh tokens
func (svc *service) generateTokens(claims tokenClaims) (*tokenDetails, error) {
	// access_token
	accessToken := &jwt.Token{
		Secret: svc.accessTokenSecret,
	}

	accessTokenClaims := make(map[string]interface{})
	for k, v := range claims {
		accessTokenClaims[k] = v
	}
	accessTokenUuid := uuid.New().String()
	accessTokenClaims["exp"] = jwt.TokenExpiry(svc.accessTokenExpiry)
	accessTokenClaims["uuid"] = accessTokenUuid

	accessTokenStr, err := accessToken.Generate(accessTokenClaims)
	if err != nil {
		return nil, err
	}

	// refresh_token
	refreshToken := &jwt.Token{
		Secret: svc.refreshTokenSecret,
	}

	refreshTokenClaims := make(map[string]interface{})
	for k, v := range claims {
		refreshTokenClaims[k] = v
	}
	refreshTokenUuid := uuid.New().String()
	refreshTokenClaims["exp"] = jwt.TokenExpiry(svc.refreshTokenExpiry)
	refreshTokenClaims["uuid"] = refreshTokenUuid

	refreshTokenTokenValue, err := refreshToken.Generate(refreshTokenClaims)
	if err != nil {
		return nil, err
	}

	return &tokenDetails{
		accessToken:        accessTokenStr,
		accessTokenUuid:    accessTokenUuid,
		accessTokenExpiry:  svc.accessTokenExpiry,
		refreshToken:       refreshTokenTokenValue,
		refreshTokenUuid:   refreshTokenUuid,
		refreshTokenExpiry: svc.refreshTokenExpiry,
	}, nil
}

// extractAccessTokenClaims will validate and extract access token claims. Access token secret is used for validation
func (svc *service) extractAccessTokenClaims(accessToken string) (map[string]interface{}, bool) {
	token := &jwt.Token{
		Secret: svc.accessTokenSecret,
	}

	return token.ValidateAndExtract(accessToken)
}

// extractRefreshTokenClaims will validate and extract refresh token. Refresh token secret is used for validation
func (svc *service) extractRefreshTokenClaims(refreshToken string) (map[string]interface{}, bool) {
	token := &jwt.Token{
		Secret: svc.refreshTokenSecret,
	}

	return token.ValidateAndExtract(refreshToken)
}

// validateCredentials will validate *User's password hash
func validateCredentials(user *User, password string) bool {
	argon := crypto.NewArgon2()

	argon.Hashed = user.Password
	argon.Plain = password

	return argon.Validate()
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

// generateAuthClaims for access token
func generateAuthClaims(sub uint, email string) tokenClaims {
	claims := make(tokenClaims)
	claims["sub"] = sub
	claims["email"] = email

	return claims
}
