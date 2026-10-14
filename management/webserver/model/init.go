package model

import (
	"gorm.io/gorm"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/management/webserver/pkg/database"
)

func InitModels() error {
	db := database.GetDB()
	err := db.Transaction(func(tx *gorm.DB) error {
		//
		if err := DBPatch140(tx); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	if err := db.AutoMigrate(&User{}, &DetectLogBasic{}, &DetectLogDetail{}, &Behaviour{}, &Options{}, &Website{}, &PolicyRule{}, &SystemStatistics{}); err != nil {
		return err
	}

	if err := initAdminUser(); err != nil {
		return err
	}

	if err := initOptions(); err != nil {
		return err
	}

	if err := initPolicyGroupGlobal(); err != nil {
		return err
	}

	if err := initSrcIPConfig(); err != nil {
		return err
	}

	//InitDetectLogSamples()

	return nil
}
