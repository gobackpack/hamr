package hamr

import (
	"fmt"
	"gorm.io/gorm"
	"time"
)

// User of the system
type User struct {
	Id               uint `gorm:"primarykey"`
	Username         string
	Email            string
	Password         string `json:"-"`
	ExternalId       string
	ExternalProvider string
	Confirmed        bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
	DeletedAt        gorm.DeletedAt `gorm:"index"`
}

// getUserByEmail will get *User by email from database.
// This user is used in authentication process (login: local + oauth) and in validation during registration process
func (svc *service) getUserByEmail(email string) *User {
	var usrEntity *User

	if result := svc.db.Where("email", email).Find(&usrEntity); result.Error != nil {
		return nil
	}

	if usrEntity.Id == 0 {
		return nil
	}

	return usrEntity
}

// addUser will create new *User in database. During registration process or first time using oauth login (auto-register)
func (svc *service) addUser(user *User) error {
	tx := svc.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Error; err != nil {
		return err
	}

	user.CreatedAt = time.Now().UTC()

	if result := tx.Create(user); result.Error != nil {
		tx.Rollback()
		return result.Error
	}

	if err := tx.Exec("INSERT INTO casbin_rule(ptype, v0, v1) VALUES (?, ?, ?)", "g", fmt.Sprint(user.Id), "user").Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// editUser will update *User. Used in authentication process (updating login provider and password)
func (svc *service) editUser(user *User) error {
	return svc.db.Save(user).Error
}
