package hamr

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"
	"time"
)

const confirmationEndpoint = "/confirm?token="

// accountConfirmation api
type accountConfirmation struct {
	tokenExpiry time.Time
	fullPath    string
	mailer      *mailer
	from        string
	Subject     string
	Body        string
	LinkText    string
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
		mailer:      newMailer(mailConfig),
		tokenExpiry: time.Now().Add(24 * time.Hour),
		from:        mailConfig.username,
		Subject:     "Account Confirmation",
		Body:        "Confirm account by clicking on the link: ",
		LinkText:    "Confirm",
	}
}

// sendConfirmationEmail will send confirmation email to user
func (accountConfirmation *accountConfirmation) sendConfirmationEmail(registeredUserEmail string, token string) error {
	endpoint := "<a href=\"" + accountConfirmation.fullPath + confirmationEndpoint + token + "\">" + accountConfirmation.LinkText + "</a>"

	return accountConfirmation.mailer.send(
		accountConfirmation.from,
		registeredUserEmail,
		"",
		"",
		accountConfirmation.Subject,
		accountConfirmation.Body+" "+endpoint)
}

// confirmAccountHandler maps to account confirmation route
func (auth *auth) confirmAccountHandler(ctx *gin.Context) {
	token := ctx.Query("token")

	if strings.TrimSpace(token) == "" {
		logrus.Error("account confirmation failed, internal error: missing token from request")
		ctx.JSON(http.StatusBadRequest, "account confirmation failed, internal error")
		return
	}

	if err := auth.service.confirmAccount(token); err != nil {
		logrus.Error("account confirmation failed, internal error: ", err)
		ctx.JSON(http.StatusBadRequest, "account confirmation failed, internal error")
		return
	}

	ctx.Redirect(http.StatusTemporaryRedirect, auth.config.basePath)
}

// confirmAccount will set confirmed to true and unset confirmation_token
func (svc *service) confirmAccount(token string) error {
	user := svc.getUserByConfirmationToken(token)

	if user == nil {
		return errors.New("invalid user")
	}

	if user.Confirmed {
		return errors.New("user account is already confirmed")
	}

	if user.ConfirmationTokenExpiry.Before(time.Now().UTC()) {
		return errors.New("confirmation token expired")
	}

	setAccountConfirmed(user)

	return svc.editUser(user)
}

// getUserByConfirmationToken will get *User by confirmation from database.
// Used for account confirmation
func (svc *service) getUserByConfirmationToken(token string) *User {
	var usrEntity *User

	if result := svc.db.Where("confirmation_token", token).Find(&usrEntity); result.Error != nil {
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
