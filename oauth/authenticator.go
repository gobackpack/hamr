package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/hamr/oauth/providers"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
	"time"
)

const (
	oAuthLoginAntiForgeryKey = "externalLoginAntiForgery"
)

// SupportedProviders are registered oauth providers for *Authenticator
var SupportedProviders = map[string]Provider{
	"google": &providers.Google{},
	"github": &providers.Github{},
}

// Authenticator is responsible for oauth logins, oAuth2 configuration setup
type Authenticator struct {
	provider Provider
	scheme   string
	host     string
	ctx      *gin.Context
	config   *oauth2.Config
}

// Provider specific requirements for *Authenticator
type Provider interface {
	Scopes() []string
	Endpoint() oauth2.Endpoint
	GetUserInfo(string) (map[string]string, error)
}

// UserInfo from oauth provider
type UserInfo struct {
	ExternalId string
	Email      string
}

// NewAuthenticator will setup *Authenticator, oAuth2 configuration
func NewAuthenticator(provider, scheme, host, port, routeGroup string, ctx *gin.Context) (*Authenticator, error) {
	providerInstance, ok := SupportedProviders[provider]
	if !ok || providerInstance == nil {
		return nil, errors.New("unsupported provider")
	}

	host = strings.Trim(host, "/")
	routeGroup = strings.Trim(routeGroup, "/")

	authenticator := &Authenticator{
		provider: providerInstance,
		scheme:   scheme,
		host:     host,
		ctx:      ctx,
		config: &oauth2.Config{
			ClientID:     viper.GetString("auth.provider." + provider + ".client_id"),
			ClientSecret: viper.GetString("auth.provider." + provider + ".client_secret"),
			RedirectURL:  scheme + "://" + host + ":" + port + "/" + routeGroup + "/" + provider + "/callback",
			Scopes:       providerInstance.Scopes(),
			Endpoint:     providerInstance.Endpoint(),
		},
	}

	return authenticator, nil
}

// RedirectToLoginUrl will redirect to oauth provider login url
func (authenticator Authenticator) RedirectToLoginUrl() {
	oAuthState, err := authenticator.setLoginAntiForgeryCookie()
	if err != nil {
		logrus.Error("failed to generate CSRF token")
		return
	}

	oAuthLoginUrl := authenticator.config.AuthCodeURL(oAuthState)

	http.Redirect(authenticator.ctx.Writer, authenticator.ctx.Request, oAuthLoginUrl, http.StatusTemporaryRedirect)
}

// GetUserInfo from oauth provider
func (authenticator Authenticator) GetUserInfo() (*UserInfo, error) {
	token, err := authenticator.exchangeCodeForToken()
	if err != nil {
		return nil, err
	}

	userData, err := authenticator.provider.GetUserInfo(token.AccessToken)
	if err != nil {
		return nil, err
	}

	if err = validateUserData(userData); err != nil {
		return nil, err
	}

	return &UserInfo{
		ExternalId: userData["externalId"],
		Email:      userData["email"],
	}, nil
}

// exchangeCodeForToken will validate state and exchange code for oauth token
func (authenticator *Authenticator) exchangeCodeForToken() (*oauth2.Token, error) {
	oAuthStateSaved, oAuthStateErr := authenticator.ctx.Request.Cookie(oAuthLoginAntiForgeryKey)
	oAuthState := authenticator.ctx.Request.FormValue("state")
	oAuthStateCode := authenticator.ctx.Request.FormValue("code")

	if oAuthStateErr != nil || oAuthState == "" {
		return nil, errors.New("invalid oAuthStateSaved/oAuthState")
	}

	if oAuthState != oAuthStateSaved.Value {
		return nil, errors.New("oAuthState do not match")
	}

	token, err := authenticator.config.Exchange(context.Background(), oAuthStateCode)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// setLoginAntiForgeryCookie will generate random state string and save it in cookies.
// CSRF protection
func (authenticator Authenticator) setLoginAntiForgeryCookie() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := base64.URLEncoding.EncodeToString(b)
	var expiration = time.Now().Add(time.Minute * time.Duration(viper.GetInt("auth.state_expiry")))

	cookie := http.Cookie{Name: oAuthLoginAntiForgeryKey, Value: state, Expires: expiration}
	http.SetCookie(authenticator.ctx.Writer, &cookie)

	return state, nil
}

// validateUserData will check if user data from oauth provider contains all required fields
func validateUserData(data map[string]string) error {
	_, ok := data["externalId"]
	if !ok {
		return errors.New("missing externalId from data")
	}

	_, ok = data["email"]
	if !ok {
		return errors.New("missing email from data")
	}

	return nil
}
