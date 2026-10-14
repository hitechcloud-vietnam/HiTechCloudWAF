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

	// Traffic counters of the local WAF engine since its start (summed over
	// sites), when the engine exposes them.
	Traffic *Traffic `json:"traffic,omitempty"`
	// Events are security events seen since the previous heartbeat.
	Events []Event `json:"events,omitempty"`
}

// Traffic is a node's request counters.
type Traffic struct {
	Requests    uint64 `json:"requests"`
	Blocked     uint64 `json:"blocked"`
	Monitored   uint64 `json:"monitored"`
	RateLimited uint64 `json:"rate_limited"`
	ACLBlocked  uint64 `json:"acl_blocked"`
	BotFailed   uint64 `json:"bot_failed"`
}

// Event is a security event reported by a node (subset of the engine's).
type Event struct {
	ID       string    `json:"id"`
	Node     string    `json:"node,omitempty"`
	Time     time.Time `json:"time"`
	Host     string    `json:"host"`
	ClientIP string    `json:"client_ip"`
	Country  string    `json:"country,omitempty"`
	Method   string    `json:"method"`
	URI      string    `json:"uri"`
	Kind     string    `json:"kind"`
	Action   string    `json:"action"`
	Status   int       `json:"status"`
	Tags     []string  `json:"tags,omitempty"`
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

	// Auth is how the last heartbeat authenticated: AuthNodeSecret or
	// AuthSharedToken (deprecated).
	Auth string `json:"auth,omitempty"`
}

// Values of Node.Auth.
const (
	AuthNodeSecret  = "node_secret"
	AuthSharedToken = "shared_token"
)

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

// DNSRecord is a static DNS record managed through the controller and served
// by every DNS server authoritative for Zone.
type DNSRecord struct {
	ID   string `json:"id"`
	Zone string `json:"zone"`
	// Name is relative to the zone: "@" for the apex, "*.app" for a
	// wildcard.
	Name string `json:"name"`
	Type string `json:"type"`
	// Value is in zone file syntax, e.g. "10 mail.example.vn." for MX.
	Value string `json:"value"`
	// TTL 0 means the zone default.
	TTL       uint32    `json:"ttl,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DNSRecordSet is the controller's answer for GET /v1/dns/records. Serial
// increases on every change and feeds the SOA serial of the DNS servers.
type DNSRecordSet struct {
	Serial  uint32      `json:"serial"`
	Records []DNSRecord `json:"records"`
}

// NodePatch is the admin request body for PATCH /v1/nodes/{id}.
type NodePatch struct {
	Drain          *bool `json:"drain,omitempty"`
	WeightOverride *int  `json:"weight_override,omitempty"`
}

// EnrollTokenRequest is the admin body for POST /v1/enroll-tokens.
type EnrollTokenRequest struct {
	// NodeID binds the token to one node ID. Empty lets the agent choose
	// its ID (configured id, else hostname), except an ID that already holds
	// an active node secret.
	NodeID string `json:"node_id,omitempty"`
	// Pools and Region, when set, are enforced on the node's heartbeats
	// instead of what the agent reports.
	Pools  []string `json:"pools,omitempty"`
	Region string   `json:"region,omitempty"`
	// ExpiresIn is the validity in seconds (default 86400, at most 30 days).
	ExpiresIn int64  `json:"expires_in,omitempty"`
	Comment   string `json:"comment,omitempty"`
}

// EnrollToken describes a one-time enrollment token. Token is only set in
// the answer that creates it; the controller keeps a hash only.
type EnrollToken struct {
	ID        string     `json:"id"`
	Token     string     `json:"token,omitempty"`
	NodeID    string     `json:"node_id,omitempty"`
	Pools     []string   `json:"pools,omitempty"`
	Region    string     `json:"region,omitempty"`
	Comment   string     `json:"comment,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	UsedBy    string     `json:"used_by,omitempty"`
	// Status is "active", "used" or "expired".
	Status string `json:"status"`
}

// EnrollRequest is the agent body for POST /v1/enroll, authenticated with
// the enrollment token.
type EnrollRequest struct {
	// ID is the node ID configured on the agent (empty when not set).
	ID string `json:"id,omitempty"`
	// Hostname becomes the node ID when neither the token nor ID sets one.
	Hostname string `json:"hostname,omitempty"`
}

// EnrollResponse carries the node secret. It is returned once; the agent
// stores it and authenticates every later call with it.
type EnrollResponse struct {
	NodeID string   `json:"node_id"`
	Secret string   `json:"secret"`
	Pools  []string `json:"pools,omitempty"`
	Region string   `json:"region,omitempty"`
}

// RotateRequest is the optional admin body for POST /v1/nodes/{id}/rotate.
type RotateRequest struct {
	ExpiresIn int64  `json:"expires_in,omitempty"`
	Comment   string `json:"comment,omitempty"`
	// RevokeCurrent revokes the node's current secret now instead of when
	// the new token is used.
	RevokeCurrent bool `json:"revoke_current,omitempty"`
}
