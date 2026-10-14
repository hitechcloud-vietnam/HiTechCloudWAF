package tools

import (
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/internal/hcw"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/internal/tools/hcwtools"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/pkg/mcp"
)

// ToolWrapper is a tool ready to register on the server.
type ToolWrapper = mcp.Registrar

var (
	tools = []ToolWrapper{}
)

// AppendTool adds tools of the legacy backend.
func AppendTool[T any, R any](tool ...mcp.Tool[T, R]) {
	for _, t := range tool {
		tools = append(tools, mcp.Wrap(t))
	}
}

// Tools returns the tools of the legacy backend.
func Tools() []ToolWrapper {
	return tools
}

// HCW returns the tools of the hcw-waf backend. readOnly leaves out every
// tool that changes a node.
func HCW(reg *hcw.Registry, readOnly bool) []ToolWrapper {
	return hcwtools.Tools(reg, readOnly)
}
