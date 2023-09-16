package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/gobackpack/hamr/oauth/models"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

const (
	oAuthLoginAntiForgeryKey = "externalLoginAntiForgery"
	stateExpiry              = time.Minute * 2
)

// SupportedProviders are registered oauth providers for *Authenticator
var SupportedProviders = map[string]Provider{}

// Authenticator is responsible for oauth logins, oAuth2 configuration setup
type Authenticator struct {
	provider Provider
	conf     *oauth2.Config
}

// Provider specific requirements for *Authenticator
type Provider interface {
	Credentials

	Scopes() []string
	Endpoint() oauth2.Endpoint
	GetUserInfo(string) (*models.UserInfo, error)
}

// Credentials for each Provider
type Credentials interface {
	ClientId() string
	ClientSecret() string
}

// NewAuthenticator will set up *Authenticator, oAuth2 configuration
func NewAuthenticator(provider, authPath string) (*Authenticator, error) {
	providerInstance, ok := SupportedProviders[provider]
	if !ok || providerInstance == nil {
		return nil, errors.New("unsupported provider: " + provider)
	}

	redirectUrl := authPath + "/" + provider + "/callback"

	return newAuthenticator(providerInstance, redirectUrl)
}

func newAuthenticator(providerInstance Provider, redirectUrl string) (*Authenticator, error) {
	auth := &Authenticator{
		provider: providerInstance,
		conf: &oauth2.Config{
			ClientID:     providerInstance.ClientId(),
			ClientSecret: providerInstance.ClientSecret(),
			RedirectURL:  redirectUrl,
			Scopes:       providerInstance.Scopes(),
			Endpoint:     providerInstance.Endpoint(),
		},
	}

	return auth, nil
}

// RedirectToLoginUrl will redirect to oauth provider login url
func (auth *Authenticator) RedirectToLoginUrl(w http.ResponseWriter, r *http.Request) {
	oAuthState, err := auth.setLoginAntiForgeryCookie(w, r)
	if err != nil {
		logrus.Error("failed to generate CSRF token")
		return
	}

	oAuthLoginUrl := auth.conf.AuthCodeURL(oAuthState)

	http.Redirect(w, r, oAuthLoginUrl, http.StatusTemporaryRedirect)
}

// GetUserInfo from oauth provider
func (auth *Authenticator) GetUserInfo(w http.ResponseWriter, r *http.Request) (*models.UserInfo, error) {
	token, err := auth.exchangeCodeForToken(w, r)
	if err != nil {
		logrus.Errorf("failed to exchange code for token: %v", err)
		return nil, errors.New("failed to get token from oauth provider")
	}

	userInfo, err := auth.provider.GetUserInfo(token.AccessToken)
	if err != nil {
		logrus.Errorf("failed to get user info from oauth provider: %v", err)
		return nil, errors.New("failed to get user info from oauth provider")
	}

	return userInfo, nil
}

// exchangeCodeForToken will validate state and exchange code for oauth token
func (auth *Authenticator) exchangeCodeForToken(w http.ResponseWriter, r *http.Request) (*oauth2.Token, error) {
	oAuthStateSaved, oAuthStateErr := r.Cookie(oAuthLoginAntiForgeryKey)
	oAuthState := r.FormValue("state")
	oAuthStateCode := r.FormValue("code")

	if oAuthStateErr != nil || oAuthState == "" {
		return nil, errors.New("invalid oAuthStateSaved/oAuthState")
	}

	if oAuthState != oAuthStateSaved.Value {
		return nil, errors.New("oAuthState do not match")
	}

	token, err := auth.conf.Exchange(context.Background(), oAuthStateCode)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// setLoginAntiForgeryCookie will generate random state string and save it in cookies.
// CSRF protection
func (auth *Authenticator) setLoginAntiForgeryCookie(w http.ResponseWriter, r *http.Request) (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := base64.URLEncoding.EncodeToString(b)
	var expiration = time.Now().Add(stateExpiry)

	cookie := http.Cookie{Name: oAuthLoginAntiForgeryKey, Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state, nil
}
