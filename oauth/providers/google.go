package providers

import (
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"net/http"
)

// Google oauth provider implementation
type Google struct{}

type googleResponse struct {
	Id    string `json:"id"`
	Email string `json:"email"`
}

func (*Google) Scopes() []string {
	return []string{"https://www.googleapis.com/auth/userinfo.email"}
}

func (*Google) Endpoint() oauth2.Endpoint {
	return google.Endpoint
}

func (*Google) GetUserData(accessToken string) (map[string]string, error) {
	exchangeUrl := "https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + accessToken

	resp, err := http.Get(exchangeUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info from code exchange: %s", err.Error())
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

	r := &googleResponse{}
	if err = json.Unmarshal(contents, &r); err != nil {
		return nil, err
	}

	oAuthClaims := make(map[string]string)
	oAuthClaims["email"] = r.Email
	oAuthClaims["externalId"] = r.Id

	return oAuthClaims, nil
}
