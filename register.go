package hamr

import (
	"encoding/json"
	"errors"
	"github.com/gobackpack/crypto"
	"github.com/sirupsen/logrus"
	"net/http"
)

/*
User registration module.
*/

// registerHandler maps to register route
func (auth *Auth) registerHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)

	var req loginRequest
	if err := decoder.Decode(&req); err != nil {
		JSON(http.StatusUnprocessableEntity, w, err.Error())
		return
	}

	var requestData map[string]interface{}
	if err := validateRequestData(requestData); err != nil {
		JSON(http.StatusUnprocessableEntity, w, err.Error())
		return
	}

	user, err := auth.registerUser(&User{
		Username: requestData["email"].(string),
		Email:    requestData["email"].(string),
		Password: requestData["password"].(string),
	}, requestData)
	if err != nil {
		JSON(http.StatusBadRequest, w, err.Error())
		return
	}

	JSON(http.StatusOK, w, user)
}

// registerUser will save user into database
func (auth *Auth) registerUser(user *User, requestData map[string]interface{}) (*User, error) {
	existingUser := auth.getUserByEmail(user.Email)
	if existingUser != nil {
		return nil, errors.New("user email is already registered")
	}

	argon := crypto.NewArgon2()

	hashed, err := argon.Hash(user.Password)
	if err != nil {
		logrus.Errorf("password hash for user %s failed: %v", user.Email, err)
		return nil, errors.New("registration failed")
	}

	user.Password = hashed
	user.LastLogin = nil

	if err := auth.addUser(user); err != nil {
		logrus.Errorf("failed to save user %s in database: %v", user.Email, err)
		return nil, errors.New("registration failed")
	}

	if auth.PostRegisterCallback != nil {
		if err := auth.PostRegisterCallback(user, requestData); err != nil {
			logrus.Errorf("PostRegisterCallback for user %s failed: %v", user.Email, err)
			return nil, err
		}
	}

	if auth.conf.accountConfirmation != nil {
		go func(user *User) {
			if err := auth.beginConfirmation(user); err != nil {
				logrus.Errorf("account confirmation failed: %v", err)
			}
		}(user)
	}

	return user, nil
}

// validateRequestData will check for required fields for registration flow
func validateRequestData(requestData map[string]interface{}) error {
	_, ok := requestData["email"]
	if !ok {
		return errors.New("missing email property")
	}

	_, ok = requestData["password"]
	if !ok {
		return errors.New("missing password property")
	}

	return nil
}
