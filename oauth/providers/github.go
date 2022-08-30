package providers

import (
	"encoding/json"
	"fmt"
	"github.com/gobackpack/hamr/oauth/models"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"io"
	"net/http"
)

// Github oauth provider implementation
type Github struct {
	clientId     string
	clientSecret string
}

type githubResponse struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

func NewGithub(clientId, clientSecret string) *Github {
	return &Github{
		clientId:     clientId,
		clientSecret: clientSecret,
	}
}

func (provider *Github) ClientId() string {
	return provider.clientId
}

func (provider *Github) ClientSecret() string {
	return provider.clientSecret
}

func (*Github) Scopes() []string {
	return []string{"user:email"}
}

func (*Github) Endpoint() oauth2.Endpoint {
	return github.Endpoint
}

func (*Github) GetUserInfo(accessToken string) (*models.UserInfo, error) {
	exchangeUrl := "https://api.github.com/user"

	req, err := http.NewRequest("GET", exchangeUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "token "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
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

	r := &githubResponse{}
	if err = json.Unmarshal(contents, &r); err != nil {
		return nil, err
	}

	return &models.UserInfo{
		ExternalId: fmt.Sprint(r.Id),
		Email:      r.Email,
	}, nil
}
