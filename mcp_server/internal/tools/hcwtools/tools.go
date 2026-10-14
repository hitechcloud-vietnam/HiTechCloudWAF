package hcwtools

import (
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/internal/hcw"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/pkg/mcp"
)

// ReadTools returns the tools that never change a node. writeTools tells
// get_node_info whether write tools are registered.
func ReadTools(reg *hcw.Registry, writeTools bool) []mcp.Registrar {
	b := base{reg: reg}
	return []mcp.Registrar{
		mcp.Wrap[InstanceParams, NodeInfoResult](GetNodeInfo{base: b, writeTools: writeTools}),
		mcp.Wrap[InstanceParams, SitesResult](ListSites{b}),
		mcp.Wrap[SiteParams, SiteResult](GetSite{b}),
		mcp.Wrap[EventsParams, EventsResult](ListAttackEvents{b}),
		mcp.Wrap[EventParams, EventResult](GetAttackEvent{b}),
		mcp.Wrap[StatsParams, StatsResult](GetStats{b}),
		mcp.Wrap[TimeseriesParams, TimeseriesResult](GetTimeseries{b}),
		mcp.Wrap[StatsParams, UpstreamsResult](GetUpstreamHealth{b}),
		mcp.Wrap[InstanceParams, ThreatIntelResult](GetThreatIntelStatus{b}),
		mcp.Wrap[CertsParams, CertsResult](ListCertificates{b}),
		mcp.Wrap[AuditParams, AuditResult](GetAuditLog{b}),
	}
}

// WriteTools returns the tools that change the configuration or the cache
// of a node.
func WriteTools(reg *hcw.Registry) []mcp.Registrar {
	b := base{reg: reg}
	return []mcp.Registrar{
		mcp.Wrap[SetModeParams, SiteChangeResult](SetSiteMode{b}),
		mcp.Wrap[IPsParams, SiteChangeResult](AddDeniedIPs{b}),
		mcp.Wrap[IPsParams, SiteChangeResult](RemoveDeniedIPs{b}),
		mcp.Wrap[RulesParams, SiteChangeResult](DisableSiteRules{b}),
		mcp.Wrap[RulesParams, SiteChangeResult](EnableSiteRules{b}),
		mcp.Wrap[PurgeParams, PurgeResult](PurgeCache{b}),
	}
}

// Tools returns the read tools and, unless readOnly, the write tools.
func Tools(reg *hcw.Registry, readOnly bool) []mcp.Registrar {
	out := ReadTools(reg, !readOnly)
	if !readOnly {
		out = append(out, WriteTools(reg)...)
	}
	return out
}
