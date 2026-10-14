// Package hcwtools implements the MCP tools of the hcw-waf backend.
//
// Reading tools live in read.go and never change a node. Tools that change
// the configuration of a node live in write.go; they are not registered at
// all when the configuration sets read_only: true, and they refuse to act on
// an instance configured with read_only: true.
package hcwtools

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/internal/hcw"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/pkg/logger"
	markmcp "github.com/mark3labs/mcp-go/mcp"
)

const instanceDescription = "Configured instance ID (see the server instructions). May be omitted when exactly one instance is configured."

func instanceOption() markmcp.ToolOption {
	return markmcp.WithString("instance_id", markmcp.MaxLength(64), markmcp.Description(instanceDescription))
}

func siteIDOption(required bool, desc string) markmcp.ToolOption {
	opts := []markmcp.PropertyOption{markmcp.Min(1), markmcp.Description(desc)}
	if required {
		opts = append(opts, markmcp.Required())
	}
	return markmcp.WithInteger("site_id", opts...)
}

// base gives every tool the instance registry.
type base struct {
	reg *hcw.Registry
}

func (b base) instance(id string) (*hcw.Instance, error) {
	return b.reg.Resolve(id)
}

// writable resolves an instance for a write tool.
func (b base) writable(id string) (*hcw.Instance, error) {
	inst, err := b.reg.Resolve(id)
	if err != nil {
		return nil, err
	}
	if inst.ReadOnly {
		return nil, errors.New("instance " + inst.InstanceID + " is configured read_only; changes are refused")
	}
	return inst, nil
}

// logWrite records a change in the server log (never the token).
func logWrite(tool string, inst *hcw.Instance, siteID int, change string) {
	logger.With("tool", tool).With("instance_id", inst.InstanceID).With("site_id", siteID).With("change", change).Info("configuration changed")
}

func timeString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func timePtrString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return timeString(*t)
}

// cleanIP returns the canonical form of a valid IP address, or "".
func cleanIP(s string) string {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return ip.Unmap().String()
}

// Counters is a set of request counters.
type Counters struct {
	Requests    int64 `json:"requests"`
	Blocked     int64 `json:"blocked"`
	Monitored   int64 `json:"monitored"`
	RateLimited int64 `json:"rate_limited"`
	ACLBlocked  int64 `json:"acl_blocked"`
	BotFailed   int64 `json:"bot_failed"`
}

func countersOf(c hcw.Counters) Counters {
	return Counters{Requests: c.Requests, Blocked: c.Blocked, Monitored: c.Monitored,
		RateLimited: c.RateLimited, ACLBlocked: c.ACLBlocked, BotFailed: c.BotFailed}
}

func (c *Counters) add(o Counters) {
	c.Requests += o.Requests
	c.Blocked += o.Blocked
	c.Monitored += o.Monitored
	c.RateLimited += o.RateLimited
	c.ACLBlocked += o.ACLBlocked
	c.BotFailed += o.BotFailed
}

// siteSummary holds the site fields the tools show.
type wireSite struct {
	ID               int      `json:"id"`
	Name             string   `json:"name"`
	ServerNames      []string `json:"server_names"`
	Ports            []string `json:"ports"`
	Upstreams        []string `json:"upstreams"`
	CertID           int      `json:"cert_id"`
	Mode             string   `json:"mode"`
	Paranoia         int      `json:"paranoia"`
	AnomalyThreshold int      `json:"anomaly_threshold"`
	DisabledRules    []int    `json:"disabled_rules"`
	RateLimit        struct {
		Requests  int `json:"requests"`
		WindowSec int `json:"window_sec"`
		BlockSec  int `json:"block_sec"`
	} `json:"rate_limit"`
	Bot struct {
		Enabled bool `json:"enabled"`
	} `json:"bot_challenge"`
	Auth struct {
		Enabled bool `json:"enabled"`
	} `json:"auth"`
	Cache struct {
		Enabled bool `json:"enabled"`
	} `json:"cache"`
	Health struct {
		Path string `json:"path"`
	} `json:"health_check"`
	Rules         []json.RawMessage `json:"rules"`
	IPAllow       []string          `json:"ip_allow"`
	IPDeny        []string          `json:"ip_deny"`
	CountryAllow  []string          `json:"country_allow"`
	CountryDeny   []string          `json:"country_deny"`
	ThreatIntel   string            `json:"threat_intel"`
	AutoTLS       bool              `json:"auto_tls"`
	RedirectHTTPS bool              `json:"redirect_https"`
	HSTS          bool              `json:"hsts"`
	CustomRules   string            `json:"custom_rules"`
	Comment       string            `json:"comment"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// SiteSummary is one line of list_sites.
type SiteSummary struct {
	ID                 int      `json:"id"`
	Name               string   `json:"name"`
	ServerNames        []string `json:"server_names"`
	Ports              []string `json:"ports"`
	Mode               string   `json:"mode"`
	Upstreams          []string `json:"upstreams"`
	CertID             int      `json:"cert_id"`
	AutoTLS            bool     `json:"auto_tls"`
	DisabledRulesCount int      `json:"disabled_rules_count"`
	IPDenyCount        int      `json:"ip_deny_count"`
	UpdatedAt          string   `json:"updated_at"`
}

// SiteDetail is the protection configuration of one site. Secrets (the
// password hash of the shared-password challenge) and the custom rule text
// are not included.
type SiteDetail struct {
	ID                int      `json:"id"`
	Name              string   `json:"name"`
	ServerNames       []string `json:"server_names"`
	Ports             []string `json:"ports"`
	Upstreams         []string `json:"upstreams"`
	Mode              string   `json:"mode"`
	CertID            int      `json:"cert_id"`
	AutoTLS           bool     `json:"auto_tls"`
	RedirectHTTPS     bool     `json:"redirect_https"`
	HSTS              bool     `json:"hsts"`
	Paranoia          int      `json:"paranoia"`
	AnomalyThreshold  int      `json:"anomaly_threshold"`
	DisabledRules     []int    `json:"disabled_rules"`
	IPAllow           []string `json:"ip_allow"`
	IPDeny            []string `json:"ip_deny"`
	CountryAllow      []string `json:"country_allow"`
	CountryDeny       []string `json:"country_deny"`
	ThreatIntel       string   `json:"threat_intel"`
	RateLimit         string   `json:"rate_limit"`
	BotChallenge      bool     `json:"bot_challenge"`
	PasswordChallenge bool     `json:"password_challenge"`
	Cache             bool     `json:"cache"`
	HealthCheckPath   string   `json:"health_check_path"`
	PathRules         int      `json:"path_rules"`
	CustomRulesBytes  int      `json:"custom_rules_bytes"`
	Comment           string   `json:"comment"`
	CreatedAt         string   `json:"created_at"`
	UpdatedAt         string   `json:"updated_at"`
}

func decodeSite(raw json.RawMessage) (wireSite, error) {
	var s wireSite
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, errors.New("unexpected site object from the node")
	}
	return s, nil
}

func ints(in []int) []int {
	out := append([]int{}, in...)
	sort.Ints(out)
	return out
}

func summaryOf(s wireSite) SiteSummary {
	return SiteSummary{
		ID: s.ID, Name: hcw.Clean(s.Name, 200), ServerNames: hcw.CleanList(s.ServerNames, 255),
		Ports: hcw.CleanList(s.Ports, 16), Mode: hcw.Clean(s.Mode, 16), Upstreams: redactURLs(s.Upstreams),
		CertID: s.CertID, AutoTLS: s.AutoTLS, DisabledRulesCount: len(s.DisabledRules), IPDenyCount: len(s.IPDeny),
		UpdatedAt: timeString(s.UpdatedAt),
	}
}

func detailOf(s wireSite) SiteDetail {
	rl := "off"
	if s.RateLimit.Requests > 0 {
		rl = strconv.Itoa(s.RateLimit.Requests) + " requests / " + strconv.Itoa(s.RateLimit.WindowSec) +
			"s per client IP, block " + strconv.Itoa(s.RateLimit.BlockSec) + "s"
	}
	return SiteDetail{
		ID: s.ID, Name: hcw.Clean(s.Name, 200), ServerNames: hcw.CleanList(s.ServerNames, 255),
		Ports: hcw.CleanList(s.Ports, 16), Upstreams: redactURLs(s.Upstreams), Mode: hcw.Clean(s.Mode, 16),
		CertID: s.CertID, AutoTLS: s.AutoTLS, RedirectHTTPS: s.RedirectHTTPS, HSTS: s.HSTS,
		Paranoia: s.Paranoia, AnomalyThreshold: s.AnomalyThreshold, DisabledRules: ints(s.DisabledRules),
		IPAllow: hcw.CleanList(s.IPAllow, 64), IPDeny: hcw.CleanList(s.IPDeny, 64),
		CountryAllow: hcw.CleanList(s.CountryAllow, 8), CountryDeny: hcw.CleanList(s.CountryDeny, 8),
		ThreatIntel: hcw.Clean(s.ThreatIntel, 32), RateLimit: rl, BotChallenge: s.Bot.Enabled,
		PasswordChallenge: s.Auth.Enabled, Cache: s.Cache.Enabled, HealthCheckPath: hcw.Clean(s.Health.Path, 200),
		PathRules: len(s.Rules), CustomRulesBytes: len(s.CustomRules), Comment: hcw.Clean(s.Comment, 500),
		CreatedAt: timeString(s.CreatedAt), UpdatedAt: timeString(s.UpdatedAt),
	}
}

func redactURLs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, u := range in {
		out = append(out, hcw.RedactURL(u))
	}
	return out
}

// siteNames maps site IDs to names; it is empty when sites cannot be read.
func siteNames(ctx context.Context, c *hcw.Client) map[int]string {
	out := map[int]string{}
	raws, err := c.Sites(ctx)
	if err != nil {
		return out
	}
	for _, raw := range raws {
		if s, err := decodeSite(raw); err == nil {
			out[s.ID] = hcw.Clean(s.Name, 200)
		}
	}
	return out
}

// sortedSiteKeys returns the numeric keys of a per-site map, sorted.
func sortedSiteKeys[T any](m map[string]T) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		if n, err := strconv.Atoi(k); err == nil {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}
