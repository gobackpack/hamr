package hamr

import (
	"errors"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type casbinRule struct {
	Id                                    uint `gorm:"primarykey"`
	ptype, v0, v1, v2, v3, v4, v5, v6, v7 string
}

var rules = []*casbinRule{
	{ptype: "p", v0: "user", v1: "res", v2: "read"},
	{ptype: "p", v0: "user", v1: "res", v2: "write"},
	{ptype: "p", v0: "user", v1: "res", v2: "delete"},
	{ptype: "g", v0: "admin", v1: "user"}, // assign user policy to admin group
	{ptype: "g", v0: "1", v1: "admin"},    // assign user id 1 admin policy
}

func seedCasbinPolicy(db *gorm.DB) {
	runTrans(db, func(tx *gorm.DB) {
		for _, rule := range rules {
			csr := &casbinRule{}
			if err := db.Table("casbin_rule").Where("ptype = ? and v0 = ? and v1 = ? and v2 = ?",
				rule.ptype, rule.v0, rule.v1, rule.v2).Find(&csr).Error; err != nil {
				logrus.Fatal(err)
			}

			if csr.Id == 0 {
				if result := tx.Exec("INSERT INTO casbin_rule(ptype, v0, v1, v2) VALUES (?, ?, ?, ?)",
					rule.ptype, rule.v0, rule.v1, rule.v2); result.Error != nil {
					tx.Rollback()
					return
				}
			}
		}
	})
}

func seed(db *gorm.DB, seeds map[interface{}]func(db *gorm.DB)) {
	for table, run := range seeds {
		if db.Migrator().HasTable(table) {
			if err := db.First(&table).Error; errors.Is(err, gorm.ErrRecordNotFound) {
				run(db)
			}
		}
	}
}

func runTrans(db *gorm.DB, trans ...func(tx *gorm.DB)) {
	tx := db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Error; err != nil {
		return
	}

	for _, tr := range trans {
		tr(tx)
	}

	tx.Commit()
}
