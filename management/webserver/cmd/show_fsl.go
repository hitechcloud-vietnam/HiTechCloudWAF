package cmd

import (
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/management/webserver/pkg/database"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/management/webserver/pkg/fvm"
)

func ShowFSL() (string, error) {
	return fvm.GenerateFullFSL(database.GetDB().DB)
}
