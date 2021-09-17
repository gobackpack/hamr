package hamr

import (
	"github.com/sirupsen/logrus"
	mail "github.com/xhit/go-simple-mail/v2"
	"time"
)

type mailer struct {
	smtpServer *mail.SMTPServer
}

type mailerConfig struct {
	host          string
	port          int
	username      string
	password      string
	useEncryption bool
}

func newMailer(config *mailerConfig) *mailer {
	server := mail.NewSMTPClient()
	server.Host = config.host
	server.Port = config.port
	server.Username = config.username
	server.Password = config.password
	server.ConnectTimeout = 10 * time.Second
	server.SendTimeout = 10 * time.Second

	if config.useEncryption {
		server.Encryption = mail.EncryptionSTARTTLS
	}

	return &mailer{
		smtpServer: server,
	}
}

func (mailer *mailer) send(from, to, cc, bcc, subject, body string) error {
	smtpClient, err := mailer.smtpServer.Connect()
	if err != nil {
		logrus.Error("smtp client failed to connect: ", err)
		return nil
	}

	email := mail.NewMSG()

	email.SetFrom(from)
	email.AddTo(to)
	email.AddCc(cc)
	email.AddBcc(bcc)
	email.SetSubject(subject)
	email.SetBody(mail.TextHTML, body)

	return email.Send(smtpClient)
}
