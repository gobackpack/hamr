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

type accountConfirmation struct {
	mailerConfig *mailerConfig
	tokenExpiry  time.Time
	fullPath     string
	mailer       *mailer
	from         string
	subject      string
	body         string
}

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
		subject:     "Account Confirmation",
		body:        "Confirm account by clicking on the link: ",
	}
}

func (accountConfirmation *accountConfirmation) sendConfirmationEmail(registeredUserEmail string, token string) error {
	endpoint := "<a href=\"" + accountConfirmation.fullPath + confirmationEndpoint + token + "\">Confirm</a>"

	return accountConfirmation.mailer.send(
		accountConfirmation.from,
		registeredUserEmail,
		"",
		"",
		accountConfirmation.subject,
		accountConfirmation.body+endpoint)
}

// registerHandler maps to register route
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
