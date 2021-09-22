package hamr

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"
	"time"
)

const confirmationEndpoint = "/confirm?token="

// accountConfirmation api
type accountConfirmation struct {
	tokenExpiry time.Duration
	fullPath    string
	mailer      *mailer
	from        string
	Subject     string
	Body        string
	LinkText    string
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
		mailer:      newMailer(mailConfig),
		from:        mailConfig.username,
		tokenExpiry: 24 * time.Hour,
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
		logrus.Error("account confirmation failed: missing token from request")
		ctx.JSON(http.StatusBadRequest, "account confirmation failed")
		return
	}

	if err := auth.confirmAccount(token); err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())
		return
	}

	ctx.Redirect(http.StatusTemporaryRedirect, auth.config.basePath)
}

// resendAccountConfirmationEmailHandler maps to resend account confirmation email route
func (auth *auth) resendAccountConfirmationEmailHandler(ctx *gin.Context) {
	requestData := &resendConfirmationRequest{}
	if err := ctx.ShouldBind(&requestData); err != nil {
		logrus.Errorf("request data binding failed: %v", err)
		ctx.JSON(http.StatusUnprocessableEntity, "invalid request data")
		return
	}

	user := auth.getUserByEmail(requestData.Email)
	if user == nil {
		ctx.JSON(http.StatusBadRequest, "user not found")
		return
	}

	if auth.config.accountConfirmation != nil && !user.Confirmed {
		if err := auth.beginConfirmation(user); err != nil {
			logrus.Errorf("account confirmation failed: %v", err)
			ctx.JSON(http.StatusBadRequest, "account confirmation failed")
			return
		}

		ctx.Redirect(http.StatusTemporaryRedirect, auth.config.basePath)
	}
}

// beginConfirmation will start the process of account confirmation.
// Assign confirmation token to user and send an email and
func (auth *auth) beginConfirmation(user *User) error {
	token := uuid.New().String()
	expiry := time.Now().UTC().Add(auth.config.accountConfirmation.tokenExpiry)
	user.ConfirmationToken = token
	user.ConfirmationTokenExpiry = &expiry

	if err := auth.editUser(user); err != nil {
		return err
	}

	return auth.config.accountConfirmation.sendConfirmationEmail(user.Email, token)
}

// confirmAccount will set confirmed to true and unset confirmation_token
func (auth *auth) confirmAccount(token string) error {
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
func (auth *auth) getUserByConfirmationToken(token string) *User {
	var usrEntity *User

	if result := auth.config.Db.Where("confirmation_token", token).Find(&usrEntity); result.Error != nil {
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
