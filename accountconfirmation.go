package hamr

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"
	"time"
)

/*
Account confirmation module.
*/

const (
	confirmationEndpoint      = "/confirm?token="
	confirmationEmailSubject  = "Account Confirmation"
	confirmationEmailBody     = "Confirm account by clicking on the link: "
	confirmationEmailLinkText = "Confirm"
)

// accountConfirmation api
type accountConfirmation struct {
	Subject  string
	Body     string
	LinkText string

	tokenExpiry time.Duration
	authPath    string
	mailer      *mailer
	from        string
}

// resendConfirmationRequest
type resendConfirmationRequest struct {
	Email string `json:"email"`
}

// NewAccountConfirmation will setup mailer and default configurations for *accountConfirmation api
func NewAccountConfirmation(host string, port int, username string, password string, useEncryption bool) *accountConfirmation {
	mailConfig := &mailerConfig{
		host:          host,
		port:          port,
		username:      username,
		password:      password,
		useEncryption: useEncryption,
	}

	return &accountConfirmation{
		Subject:     confirmationEmailSubject,
		Body:        confirmationEmailBody,
		LinkText:    confirmationEmailLinkText,
		mailer:      newMailer(mailConfig),
		from:        mailConfig.username,
		tokenExpiry: 24 * time.Hour,
	}
}

// sendConfirmationEmail will send confirmation email to user
func (accountConfirmation *accountConfirmation) sendConfirmationEmail(registeredUserEmail string, token string) error {
	endpoint := "<a href=\"" + accountConfirmation.authPath + confirmationEndpoint + token + "\">" + accountConfirmation.LinkText + "</a>"

	return accountConfirmation.mailer.send(
		accountConfirmation.from,
		registeredUserEmail,
		"",
		"",
		accountConfirmation.Subject,
		accountConfirmation.Body+" "+endpoint)
}

// confirmAccountHandler maps to account confirmation route
func (auth *Auth) confirmAccountHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	if strings.TrimSpace(token) == "" {
		logrus.Error("account confirmation failed: missing token from request")
		JSON(http.StatusBadRequest, w, "account confirmation failed")
		return
	}

	if err := auth.confirmAccount(token); err != nil {
		JSON(http.StatusBadRequest, w, err.Error())
		return
	}

	http.Redirect(w, r, auth.conf.basePath, http.StatusTemporaryRedirect)
}

// resendAccountConfirmationEmailHandler maps to resend account confirmation email route
func (auth *Auth) resendAccountConfirmationEmailHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	requestData := &resendConfirmationRequest{}

	if err := decoder.Decode(&requestData); err != nil {
		JSON(http.StatusUnprocessableEntity, w, "invalid request data")
		return
	}

	user := auth.getUserByEmail(requestData.Email)
	if user == nil {
		JSON(http.StatusBadRequest, w, "user not found")
		return
	}

	if auth.conf.accountConfirmation != nil && !user.Confirmed {
		if err := auth.beginConfirmation(user); err != nil {
			logrus.Errorf("account confirmation failed: %v", err)
			JSON(http.StatusBadRequest, w, "account confirmation failed")
			return
		}

		http.Redirect(w, r, auth.conf.basePath, http.StatusTemporaryRedirect)
	}
}

// beginConfirmation will start the process of account confirmation.
// Assign confirmation token to user and send an email and
func (auth *Auth) beginConfirmation(user *User) error {
	token := uuid.New().String()
	expiry := time.Now().UTC().Add(auth.conf.accountConfirmation.tokenExpiry)
	user.ConfirmationToken = token
	user.ConfirmationTokenExpiry = &expiry

	if err := auth.editUser(user); err != nil {
		return err
	}

	return auth.conf.accountConfirmation.sendConfirmationEmail(user.Email, token)
}

// confirmAccount will set confirmed to true and unset confirmation_token
func (auth *Auth) confirmAccount(token string) error {
	user := auth.getUserByConfirmationToken(token)

	if user == nil {
		return errors.New("confirmation token does not exist")
	}

	if user.Confirmed {
		return errors.New("user account is already confirmed")
	}

	if user.ConfirmationTokenExpiry.Before(time.Now().UTC()) {
		return errors.New("confirmation token expired")
	}

	setAccountConfirmed(user)

	if err := auth.editUser(user); err != nil {
		logrus.Errorf("failed to update user %s during account confirmation: %v", user.Email, err)
		return errors.New("account confirmation failed")
	}

	return nil
}

// getUserByConfirmationToken will get *User by confirmation from database.
// Used for account confirmation
func (auth *Auth) getUserByConfirmationToken(token string) *User {
	var usrEntity *User

	if result := auth.conf.Db.Where("confirmation_token", token).Find(&usrEntity); result.Error != nil {
		return nil
	}

	if usrEntity.Id == 0 {
		return nil
	}

	return usrEntity
}

// setAccountConfirmed will set Confirmed to true and reset other confirmation fields to zero values
func setAccountConfirmed(user *User) {
	user.Confirmed = true
	user.ConfirmationToken = ""
	user.ConfirmationTokenExpiry = nil
}
