//go:build !linux

package agent

import (
	"runtime"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
)

func collectStats(string) api.Stats { return api.Stats{CPUs: runtime.NumCPU()} }
