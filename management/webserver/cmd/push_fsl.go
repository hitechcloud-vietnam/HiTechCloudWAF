package cmd

import (
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/management/webserver/pkg/database"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/management/webserver/pkg/fvm"
)

func PushFSL() error {
	return fvm.PushFSL(database.GetDB().DB)
}
