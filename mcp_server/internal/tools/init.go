package tools

import (
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/internal/tools/analyze"
)

func init() {
	AppendTool(&analyze.GetAttackEvents{})
}
