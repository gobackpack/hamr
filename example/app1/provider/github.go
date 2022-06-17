package provider

import (
	"encoding/json"
	"fmt"
	"github.com/gobackpack/hamr/oauth/models"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"io/ioutil"
	"net/http"
)

type CustomGithubProvider struct {
	clientId     string
	clientSecret string
}

type githubResponse struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

func NewCustomGithub(clientId, clientSecret string) *CustomGithubProvider {
	return &CustomGithubProvider{
		clientId:     clientId,
		clientSecret: clientSecret,
	}
}

func (provider *CustomGithubProvider) ClientId() string {
	return provider.clientId
}

func (provider *CustomGithubProvider) ClientSecret() string {
	return provider.clientSecret
}

func (*CustomGithubProvider) Scopes() []string {
	return []string{"user:email"}
}

func (*CustomGithubProvider) Endpoint() oauth2.Endpoint {
	return github.Endpoint
}

func (*CustomGithubProvider) GetUserInfo(accessToken string) (*models.UserInfo, error) {
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

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read code exchange response: %s", err.Error())
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
