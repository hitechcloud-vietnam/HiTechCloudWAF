// Package api holds the wire types shared by the controller, the node agent
// and the DNS server of a HiTechCloud WAF cluster.
package api

import (
	"encoding/json"
	"time"
)

// Heartbeat is what a node agent reports to the controller.
type Heartbeat struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Region  string            `json:"region"`
	Pools   []string          `json:"pools"`
	IPv4    string            `json:"ipv4"`
	IPv6    string            `json:"ipv6,omitempty"`
	Weight  int               `json:"weight"`
	Labels  map[string]string `json:"labels,omitempty"`
	Version string            `json:"version"`

	// ProbeURL is what the controller requests to decide whether the WAF on
	// this node serves traffic. Empty means "trust the heartbeat only".
	ProbeURL string `json:"probe_url,omitempty"`

	EngineHealthy bool   `json:"engine_healthy"`
	EngineError   string `json:"engine_error,omitempty"`

	ConfigRevision string `json:"config_revision,omitempty"`
	ConfigError    string `json:"config_error,omitempty"`

	Stats Stats `json:"stats"`
}

// Stats are point-in-time host metrics from the node.
type Stats struct {
	Load1       float64 `json:"load1"`
	Load5       float64 `json:"load5"`
	Load15      float64 `json:"load15"`
	CPUs        int     `json:"cpus"`
	MemTotalMB  uint64  `json:"mem_total_mb"`
	MemAvailMB  uint64  `json:"mem_avail_mb"`
	UptimeSec   uint64  `json:"uptime_sec"`
	DiskFreeMB  uint64  `json:"disk_free_mb"`
	DiskTotalMB uint64  `json:"disk_total_mb"`
}

// Node is the controller's view of a cluster member.
type Node struct {
	Heartbeat

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// Drain removes the node from DNS answers without removing it from the
	// cluster, e.g. for maintenance.
	Drain bool `json:"drain"`
	// WeightOverride, when > 0, replaces the weight the agent reports.
	WeightOverride int `json:"weight_override,omitempty"`

	ProbeOK     bool      `json:"probe_ok"`
	ProbeError  string    `json:"probe_error,omitempty"`
	ProbeAt     time.Time `json:"probe_at,omitempty"`
	ProbeMillis int64     `json:"probe_ms"`

	// Healthy is derived: fresh heartbeat, engine healthy and probe passing.
	Healthy bool   `json:"healthy"`
	Reason  string `json:"reason,omitempty"`
}

// EffectiveWeight is the weight used for DNS answers.
func (n *Node) EffectiveWeight() int {
	if n.WeightOverride > 0 {
		return n.WeightOverride
	}
	if n.Weight > 0 {
		return n.Weight
	}
	return 100
}

// Endpoint is one address the DNS server may hand out for a pool.
type Endpoint struct {
	NodeID  string `json:"node_id"`
	Name    string `json:"name"`
	Region  string `json:"region"`
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
	Weight  int    `json:"weight"`
	Healthy bool   `json:"healthy"`
}

// PoolEndpoints is the controller's answer for /v1/pools/{pool}/endpoints.
type PoolEndpoints struct {
	Pool      string     `json:"pool"`
	Endpoints []Endpoint `json:"endpoints"`
}

// Snapshot is the configuration replicated from the primary WAF engine to
// every node. Items keep the primary's IDs so references can be remapped.
type Snapshot struct {
	Revision  string                       `json:"revision"`
	CreatedAt time.Time                    `json:"created_at"`
	Resources map[string][]json.RawMessage `json:"resources"`
}

// NodePatch is the admin request body for PATCH /v1/nodes/{id}.
type NodePatch struct {
	Drain          *bool `json:"drain,omitempty"`
	WeightOverride *int  `json:"weight_override,omitempty"`
}
