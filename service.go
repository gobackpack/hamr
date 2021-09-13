package hamr

import (
	"errors"
	"fmt"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gobackpack/crypto"
	"github.com/gobackpack/hamr/external"
	"github.com/gobackpack/hamr/internal/cache"
	"github.com/gobackpack/hamr/models"
	"github.com/gobackpack/jwt"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

// service for authentication. Exposes services for register, login, logout, refreshToken
type service struct {
	accessTokenSecret  []byte
	accessTokenExpiry  time.Duration
	refreshTokenSecret []byte
	refreshTokenExpiry time.Duration

	cache         cache.Storage
	casbinAdapter *gormadapter.Adapter
	db            *gorm.DB

	PostRegisterCallback func(user *models.User) error
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

// tokenClaims contains required claims/properties for authentication (sub + email). Validated in: validateClaims(claims tokenClaims)
type tokenClaims map[string]interface{}

// tokensMap contains generated access_token and refresh_token after authentication. These token pairs are returned to the user
type tokensMap map[string]string

// registerUser will save user into database
func (svc *service) registerUser(user *models.User) (*models.User, error) {
	existing := svc.getUserByEmail(user.Email)
	if existing != nil {
		return nil, errors.New(fmt.Sprintf("user email or username is already registered: %v, %v", user.Username, user.Email))
	}

	argon := crypto.NewArgon2()
	argon.Plain = user.Password

	if err := argon.Hash(); err != nil {
		return nil, err
	}

	user.Password = argon.Hashed

	if err := svc.addUser(user); err != nil {
		return nil, err
	}

	if svc.PostRegisterCallback != nil {
		if err := svc.PostRegisterCallback(user); err != nil {
			return nil, err
		}
	}

	return user, nil
}

// authenticate will login user. Validate credentials and save tokens in cache
func (svc *service) authenticate(email, password string) (tokensMap, error) {
	user := svc.getUserByEmail(email)
	if user == nil {
		return nil, errors.New("user email not registered: " + email)
	}

	claims := make(tokenClaims)
	claims["sub"] = user.Id
	claims["email"] = user.Email

	// user previously registered using local register (email + pwd), password already exists
	// just validate credentials
	if user.Password != "" && validateCredentials(user, password) {
		tokens, err := svc.createAuth(claims)
		if err != nil {
			return nil, err
		}

		return tokens, nil
	} else if user.Password == "" && user.ExternalId != "" {
		// user previously registered with external provider (etc. google)
		// password does not exist, create new
		argon := crypto.NewArgon2()
		argon.Plain = password

		if err := argon.Hash(); err != nil {
			return nil, err
		}

		user.Password = argon.Hashed

		if err := svc.editUser(user); err != nil {
			return nil, err
		}

		tokens, err := svc.createAuth(claims)
		if err != nil {
			return nil, err
		}

		return tokens, nil
	}

	return nil, errors.New("invalid credentials")
}

// authenticateExternal will login user using external providers (google...), save tokens in cache
func (svc *service) authenticateExternal(externalClaims *external.OAuthClaims, provider string) (tokensMap, error) {
	email := externalClaims.Email
	externalId := externalClaims.Id

	user := svc.getUserByEmail(email)
	if user == nil {
		user = &models.User{
			Email:            email,
			Username:         email,
			ExternalId:       externalId,
			ExternalProvider: provider,
			Confirmed:        true,
		}

		if err := svc.addUser(user); err != nil {
			return nil, err
		}

		if svc.PostRegisterCallback != nil {
			if err := svc.PostRegisterCallback(user); err != nil {
				return nil, err
			}
		}
	} else {
		user.ExternalId = externalId
		user.ExternalProvider = provider

		if err := svc.editUser(user); err != nil {
			return nil, err
		}
	}

	claims := make(tokenClaims)
	claims["sub"] = user.Id
	claims["email"] = user.Email

	tokens, err := svc.createAuth(claims)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

// destroyAuthenticationSession will logout user. Remove access and refresh tokens from cache
func (svc *service) destroyAuthenticationSession(accessToken, refreshToken string) error {
	accessTokenClaims, aValid := svc.extractAccessTokenClaims(accessToken)
	if !aValid {
		return errors.New("invalid access_token")
	}

	refreshTokenClaims, rValid := svc.extractRefreshTokenClaims(refreshToken)
	if !rValid {
		return errors.New("invalid refresh_token")
	}

	accessTokenUuid := accessTokenClaims["uuid"]
	accessTokenUserId := accessTokenClaims["sub"]
	if accessTokenUuid == nil || accessTokenUserId == nil {
		return errors.New("invalid claims from access_token")
	}

	refreshTokenUuid := refreshTokenClaims["uuid"]
	refreshTokenUserId := refreshTokenClaims["sub"]
	if refreshTokenUuid == nil || refreshTokenUserId == nil {
		return errors.New("invalid claims from refresh_token")
	}

	if accessTokenUserId != refreshTokenUserId {
		return errors.New("access_token sub does not match refresh_token sub")
	}

	if err := svc.cache.Delete(fmt.Sprint(accessTokenUuid), fmt.Sprint(refreshTokenUuid)); err != nil {
		return err
	}

	return nil
}

// refreshToken will generate new pair of access and refresh tokens. Remove old access and refresh tokens from cache
func (svc *service) refreshToken(accessToken, refreshToken string) (tokensMap, error) {
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

	// make sure refresh token is still active
	_, err := svc.cache.Get(fmt.Sprint(refreshTokenUuid))
	if err != nil {
		return nil, errors.New("refresh_token is no longer active")
	}

	// get old access token uuid so it can be deleted from cache
	// we do not need to validate it - it's already expired, probably does not even exists!
	accessTokenClaims, _ := svc.extractAccessTokenClaims(accessToken)
	accessTokenUuid := accessTokenClaims["uuid"]
	accessTokenUserId := accessTokenClaims["sub"]
	if accessTokenUuid == nil || accessTokenUserId == nil {
		return nil, errors.New("invalid claims from access_token")
	}

	if refreshTokenUserId != accessTokenUserId {
		return nil, errors.New("access_token sub does not match refresh_token sub")
	}

	// safe to delete both access and refresh tokens from cache, though access token is probably already deleted

	// delete refresh token uuid
	if err = svc.cache.Delete(fmt.Sprint(refreshTokenUuid), fmt.Sprint(accessTokenUuid)); err != nil {
		return nil, err
	}

	// generate new access token and refresh token
	claims := make(tokenClaims)
	claims["sub"] = refreshTokenUserId
	claims["email"] = refreshTokenUserEmail

	tokens, err := svc.createAuth(claims)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

// createAuth will create *User login session. Generate access and refresh tokens and save both tokens in cache storage
func (svc *service) createAuth(claims tokenClaims) (tokensMap, error) {
	if err := validateClaims(claims); err != nil {
		return nil, err
	}

	td, err := svc.generateTokens(claims)
	if err != nil {
		return nil, err
	}

	userId := claims["sub"]

	if err = svc.cache.Store(
		&cache.Item{
			Key:        td.accessTokenUuid,
			Value:      userId,
			Expiration: td.accessTokenExpiry,
		}, &cache.Item{
			Key:        td.refreshTokenUuid,
			Value:      userId,
			Expiration: td.refreshTokenExpiry,
		}); err != nil {
		return nil, err
	}

	tokens := make(tokensMap)
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
func validateCredentials(user *models.User, password string) bool {
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
