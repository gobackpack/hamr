package providers

import (
	"encoding/json"
	"github.com/gobackpack/hamr/oauth/models"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"net/http"
)

// Google oauth provider implementation
type Google struct {
	clientId     string
	clientSecret string
}

type googleResponse struct {
	Id    string `json:"id"`
	Email string `json:"email"`
}

func NewGoogle(clientId, clientSecret string) *Google {
	return &Google{
		clientId:     clientId,
		clientSecret: clientSecret,
	}
}

func (provider *Google) ClientId() string {
	return provider.clientId
}

func (provider *Google) ClientSecret() string {
	return provider.clientSecret
}

func (*Google) Scopes() []string {
	return []string{"https://www.googleapis.com/auth/userinfo.email"}
}

func (*Google) Endpoint() oauth2.Endpoint {
	return google.Endpoint
}

func (*Google) GetUserInfo(accessToken string) (*models.UserInfo, error) {
	exchangeUrl := "https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + accessToken

	resp, err := http.Get(exchangeUrl)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logrus.Error("failed to close code exchange http response: ", err.Error())
			return
		}
	}()

	contents, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	r := &googleResponse{}
	if err = json.Unmarshal(contents, &r); err != nil {
		return nil, err
	}

	return &models.UserInfo{
		ExternalId: r.Id,
		Email:      r.Email,
	}, nil
}
