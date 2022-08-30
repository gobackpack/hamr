package hamr

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gobackpack/crypto"
	"github.com/gobackpack/hamr/oauth"
	"github.com/gobackpack/hamr/oauth/models"
	"github.com/sirupsen/logrus"
	"net/http"
	"time"
)

/*
Login module.
*/

// loginRequest http API model
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// loginHandler maps to local (email + pwd) login route
func (auth *auth) loginHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)

	var req loginRequest
	if err := decoder.Decode(&req); err != nil {
		JSON(http.StatusUnprocessableEntity, w, err.Error())
		return
	}

	tokens, err := auth.authenticate(req.Email, req.Password)
	if err != nil {
		JSON(http.StatusBadRequest, w, err.Error())
		return
	}

	JSON(http.StatusOK, w, tokens)
}

// oauthLoginHandler maps to :provider login route. Redirects to :provider oAuth login url
func (auth *auth) oauthLoginHandler(provider string, w http.ResponseWriter, r *http.Request) {
	authenticator, err := oauth.NewAuthenticator(provider, auth.conf.authPath)
	if err != nil {
		JSON(http.StatusBadRequest, w, err.Error())
		return
	}

	authenticator.RedirectToLoginUrl(w, r)
}

// oauthLoginCallbackHandler maps to :provider login callback route. After login :provider redirects to this route
func (auth *auth) oauthLoginCallbackHandler(provider string, w http.ResponseWriter, r *http.Request) {
	authenticator, err := oauth.NewAuthenticator(provider, auth.conf.authPath)
	if err != nil {
		JSON(http.StatusBadRequest, w, err.Error())
		return
	}

	userInfo, err := authenticator.GetUserInfo(w, r)
	if err != nil {
		JSON(http.StatusBadRequest, w, err.Error())
		return
	}

	tokens, err := auth.authenticateWithOAuth(userInfo, provider)
	if err != nil {
		JSON(http.StatusBadRequest, w, err.Error())
		return
	}

	JSON(http.StatusOK, w, tokens)
}

// authenticate will login user with local login (email + pwd), validate credentials and save tokens in cache
func (auth *auth) authenticate(email, password string) (authTokens, error) {
	user := auth.getUserByEmail(email)
	if user == nil {
		return nil, errors.New(fmt.Sprintf("user email %s not registered", email))
	}

	if auth.conf.accountConfirmation != nil && !user.Confirmed {
		return nil, errors.New("user account not confirmed")
	}

	claims := generateAuthClaims(user.Id, user.Email)
	lastLogin := time.Now().UTC()

	// user previously registered using local register (email + pwd)
	// password exists, validate credentials
	if user.Password != "" && validateCredentials(user, password) {
		user.LastLogin = &lastLogin

		if err := auth.editUser(user); err != nil {
			logrus.Errorf("updating user %s during authentication failed: %v", email, err)
			return nil, errors.New("authentication failed")
		}

		tokens, err := auth.createSession(claims)
		if err != nil {
			logrus.Errorf("user %s failed to authenticate: %v", email, err)
			return nil, errors.New("authentication failed")
		}

		return tokens, nil
	} else if user.Password == "" && user.ExternalProvider != "" {
		return nil, errors.New(fmt.Sprintf("please login with your %s account or set new password from account settings", user.ExternalProvider))
	}

	return nil, errors.New("invalid credentials")
}

// authenticateWithOAuth will login user with oauth provider (google, github...), save tokens in cache
func (auth *auth) authenticateWithOAuth(userInfo *models.UserInfo, provider string) (authTokens, error) {
	externalId := userInfo.ExternalId
	email := userInfo.Email

	user := auth.getUserByEmail(email)
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

		if err := auth.addUser(user); err != nil {
			logrus.Errorf("failed to save user %s in database: %v", email, err)
			return nil, errors.New("authentication failed")
		}

		if auth.PostRegisterCallback != nil {
			if err := auth.PostRegisterCallback(user, nil); err != nil {
				logrus.Errorf("PostRegisterCallback for user %s failed: %v", user.Email, err)
				return nil, err
			}
		}
	} else {
		user.ExternalId = externalId
		user.ExternalProvider = provider
		user.LastLogin = &lastLogin

		setAccountConfirmed(user)

		if err := auth.editUser(user); err != nil {
			logrus.Errorf("updating user %s during authentication failed: %v", email, err)
			return nil, errors.New("authentication failed")
		}
	}

	claims := generateAuthClaims(user.Id, user.Email)

	tokens, err := auth.createSession(claims)
	if err != nil {
		logrus.Errorf("user %s failed to authenticate: %v", email, err)
		return nil, errors.New("authentication failed")
	}

	return tokens, nil
}

// validateCredentials will validate *User's password hash
func validateCredentials(user *User, password string) bool {
	argon := crypto.NewArgon2()

	argon.Hashed = user.Password
	argon.Plain = password

	return argon.Validate()
}
