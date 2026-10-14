package cmd

import "github.com/hitechcloud-vietnam/HiTechCloudWAF/management/webserver/model"

func FakeLogs() {
	model.InitDetectLogSamples()
}
