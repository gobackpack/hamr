package providers

import (
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"io/ioutil"
	"net/http"
)

// Github external *Authenticator provider implementation
type Github struct{}

type githubResponse struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

func (*Github) Scopes() []string {
	return []string{"user:email"}
}

func (*Github) Endpoint() oauth2.Endpoint {
	return github.Endpoint
}

func (*Github) GetUserData(accessToken string) (map[string]string, error) {
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

	oAuthClaims := make(map[string]string)
	oAuthClaims["email"] = r.Email
	oAuthClaims["externalId"] = fmt.Sprint(r.Id)

	return oAuthClaims, nil
}
