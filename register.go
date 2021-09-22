package hamr

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/gobackpack/crypto"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"net/http"
)

// registerHandler maps to register route
func (auth *auth) registerHandler(ctx *gin.Context) {
	var requestData map[string]interface{}
	if err := ctx.ShouldBind(&requestData); err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	if err := validateRequestData(requestData); err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	user, err := auth.registerUser(&User{
		Username: requestData["email"].(string),
		Email:    requestData["email"].(string),
		Password: requestData["password"].(string),
	}, requestData)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())
		return
	}

	ctx.JSON(http.StatusOK, user)
}

// registerUser will save user into database
func (auth *auth) registerUser(user *User, requestData map[string]interface{}) (*User, error) {
	existingUser := auth.getUserByEmail(user.Email)
	if existingUser != nil {
		return nil, errors.New("user email is already registered")
	}

	argon := crypto.NewArgon2()
	argon.Plain = user.Password

	if err := argon.Hash(); err != nil {
		logrus.Errorf("password hash for user %s failed: %v", user.Email, err)
		return nil, errors.New("registration failed")
	}

	user.Password = argon.Hashed
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

	if auth.config.accountConfirmation != nil {
		go func(user *User) {
			token := uuid.New().String()
			if err := auth.config.accountConfirmation.sendConfirmationEmail(user.Email, token); err != nil {
				logrus.Errorf("send account confirmation to email %s failed: %v", user.Email, err)
			}

			user.ConfirmationToken = token
			user.ConfirmationTokenExpiry = &auth.config.accountConfirmation.tokenExpiry

			if err := auth.editUser(user); err != nil {
				logrus.Errorf("update account confirmation for user %s failed: %v", user.Email, err)
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
