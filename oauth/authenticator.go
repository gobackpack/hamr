package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/hamr/oauth/models"
	"github.com/gobackpack/hamr/oauth/providers"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

const (
	oAuthLoginAntiForgeryKey = "externalLoginAntiForgery"
)

// SupportedProviders are registered oauth providers for *authenticator
var SupportedProviders = map[string]Provider{
	"google": &providers.Google{},
	"github": &providers.Github{},
}

// authenticator is responsible for oauth logins, oAuth2 configuration setup
type authenticator struct {
	provider Provider
	ctx      *gin.Context
	config   *oauth2.Config
}

// Provider specific requirements for *authenticator
type Provider interface {
	Scopes() []string
	Endpoint() oauth2.Endpoint
	GetUserInfo(string) (*models.UserInfo, error)
}

// NewAuthenticator will setup *authenticator, oAuth2 configuration
func NewAuthenticator(provider, fullPath string, ctx *gin.Context) (*authenticator, error) {
	providerInstance, ok := SupportedProviders[provider]
	if !ok || providerInstance == nil {
		return nil, errors.New("unsupported provider")
	}

	auth := &authenticator{
		provider: providerInstance,
		ctx:      ctx,
		config: &oauth2.Config{
			ClientID:     viper.GetString("auth.provider." + provider + ".client_id"),
			ClientSecret: viper.GetString("auth.provider." + provider + ".client_secret"),
			RedirectURL:  fullPath + "/" + provider + "/callback",
			Scopes:       providerInstance.Scopes(),
			Endpoint:     providerInstance.Endpoint(),
		},
	}

	return auth, nil
}

// RedirectToLoginUrl will redirect to oauth provider login url
func (auth *authenticator) RedirectToLoginUrl() {
	oAuthState, err := auth.setLoginAntiForgeryCookie()
	if err != nil {
		logrus.Error("failed to generate CSRF token")
		return
	}

	oAuthLoginUrl := auth.config.AuthCodeURL(oAuthState)

	http.Redirect(auth.ctx.Writer, auth.ctx.Request, oAuthLoginUrl, http.StatusTemporaryRedirect)
}

// GetUserInfo from oauth provider
func (auth *authenticator) GetUserInfo() (*models.UserInfo, error) {
	token, err := auth.exchangeCodeForToken()
	if err != nil {
		return nil, err
	}

	return auth.provider.GetUserInfo(token.AccessToken)
}

// exchangeCodeForToken will validate state and exchange code for oauth token
func (auth *authenticator) exchangeCodeForToken() (*oauth2.Token, error) {
	oAuthStateSaved, oAuthStateErr := auth.ctx.Request.Cookie(oAuthLoginAntiForgeryKey)
	oAuthState := auth.ctx.Request.FormValue("state")
	oAuthStateCode := auth.ctx.Request.FormValue("code")

	if oAuthStateErr != nil || oAuthState == "" {
		return nil, errors.New("invalid oAuthStateSaved/oAuthState")
	}

	if oAuthState != oAuthStateSaved.Value {
		return nil, errors.New("oAuthState do not match")
	}

	token, err := auth.config.Exchange(context.Background(), oAuthStateCode)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// setLoginAntiForgeryCookie will generate random state string and save it in cookies.
// CSRF protection
func (auth *authenticator) setLoginAntiForgeryCookie() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := base64.URLEncoding.EncodeToString(b)
	var expiration = time.Now().Add(time.Minute * time.Duration(viper.GetInt("auth.state_expiry")))

	cookie := http.Cookie{Name: oAuthLoginAntiForgeryKey, Value: state, Expires: expiration}
	http.SetCookie(auth.ctx.Writer, &cookie)

	return state, nil
}
