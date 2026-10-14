package hcw

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Paths of the management API (docs/api/waf.openapi.yaml).
const (
	pathInfo        = "/api/open/info"
	pathSites       = "/api/open/site"
	pathCerts       = "/api/open/cert"
	pathEvents      = "/api/open/events"
	pathStats       = "/api/open/stats"
	pathTimeseries  = "/api/open/timeseries"
	pathUpstreams   = "/api/open/upstreams"
	pathThreatIntel = "/api/open/threatintel"
	pathCache       = "/api/open/cache"
	pathCachePurge  = "/api/open/cache/purge"
	pathAudit       = "/api/open/audit"

	// MaxEventsFetch is the most events the node returns in one answer.
	MaxEventsFetch = 1000
	// MaxAuditFetch is the most audit entries the node returns.
	MaxAuditFetch = 2000
)

type list[T any] struct {
	Data  []T `json:"data"`
	Total int `json:"total"`
}

// WireEvent is an event as the node sends it.
type WireEvent struct {
	ID       string     `json:"id"`
	Time     time.Time  `json:"time"`
	SiteID   int        `json:"site_id"`
	Host     string     `json:"host"`
	ClientIP string     `json:"client_ip"`
	Country  string     `json:"country"`
	Method   string     `json:"method"`
	URI      string     `json:"uri"`
	UA       string     `json:"user_agent"`
	Kind     string     `json:"kind"`
	Action   string     `json:"action"`
	Feed     string     `json:"feed"`
	Status   int        `json:"status"`
	Rules    []WireRule `json:"rules"`
	Tags     []string   `json:"tags"`
}

// WireRule is a matched rule of an event.
type WireRule struct {
	ID       int    `json:"id"`
	Msg      string `json:"msg"`
	Data     string `json:"data"`
	Severity string `json:"severity"`
}

// Counters are per-site counters.
type Counters struct {
	Requests    int64 `json:"requests"`
	Blocked     int64 `json:"blocked"`
	Monitored   int64 `json:"monitored"`
	RateLimited int64 `json:"rate_limited"`
	ACLBlocked  int64 `json:"acl_blocked"`
	BotFailed   int64 `json:"bot_failed"`
}

// Bucket is one minute of node-wide counters.
type Bucket struct {
	Minute int64 `json:"minute"`
	Counters
}

// WireUpstream is the health of one upstream.
type WireUpstream struct {
	URL       string    `json:"url"`
	Healthy   bool      `json:"healthy"`
	Checked   bool      `json:"checked"`
	LastCheck time.Time `json:"last_check"`
	LastError string    `json:"last_error"`
}

// WireFeed is the status of one threat-intelligence feed.
type WireFeed struct {
	Name       string     `json:"name"`
	URL        string     `json:"url"`
	RefreshSec int        `json:"refresh_sec"`
	Entries    int        `json:"entries"`
	Ranges     int        `json:"ranges"`
	Invalid    int        `json:"invalid_lines"`
	Source     string     `json:"source"`
	UpdatedAt  *time.Time `json:"updated_at"`
	CheckedAt  *time.Time `json:"checked_at"`
	NextAt     *time.Time `json:"next_at"`
	LastError  string     `json:"last_error"`
}

// WireCert holds the certificate fields this server reads. The private key
// ("key") and the PEM chain are deliberately not part of it.
type WireCert struct {
	ID        int       `json:"id"`
	Domains   []string  `json:"domains"`
	Issuer    string    `json:"issuer"`
	NotAfter  time.Time `json:"not_after"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// WireAudit is one audit log entry.
type WireAudit struct {
	Time   time.Time       `json:"time"`
	User   string          `json:"user"`
	IP     string          `json:"ip"`
	Action string          `json:"action"`
	Status int             `json:"status"`
	Detail json.RawMessage `json:"detail"`
}

// WireInfo is the node information.
type WireInfo struct {
	Version   string    `json:"version"`
	StartedAt time.Time `json:"started_at"`
	Sites     int       `json:"sites"`
	Certs     int       `json:"certs"`
}

// CacheStats is the response cache usage.
type CacheStats struct {
	Objects int64 `json:"objects"`
	Bytes   int64 `json:"bytes"`
}

// Info returns the node version and object counts.
func (c *Client) Info(ctx context.Context) (WireInfo, error) {
	var v WireInfo
	return v, c.Do(ctx, http.MethodGet, pathInfo, nil, nil, &v)
}

// Cache returns the response cache usage.
func (c *Client) Cache(ctx context.Context) (CacheStats, error) {
	var v CacheStats
	return v, c.Do(ctx, http.MethodGet, pathCache, nil, nil, &v)
}

// Sites returns every site as raw JSON, so that a modification keeps the
// fields this server does not know about.
func (c *Client) Sites(ctx context.Context) ([]json.RawMessage, error) {
	var l list[json.RawMessage]
	if err := c.Do(ctx, http.MethodGet, pathSites, nil, nil, &l); err != nil {
		return nil, err
	}
	return l.Data, nil
}

// Site returns one raw site.
func (c *Client) Site(ctx context.Context, id int) (json.RawMessage, error) {
	all, err := c.Sites(ctx)
	if err != nil {
		return nil, err
	}
	for _, raw := range all {
		var s struct {
			ID int `json:"id"`
		}
		if json.Unmarshal(raw, &s) == nil && s.ID == id {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("site %d not found (see list_sites)", id)
}

// SiteChange edits the raw fields of a site and describes the change; an
// empty description means nothing changed and nothing is written.
type SiteChange func(m map[string]json.RawMessage) (string, error)

// ModifySite reads site id, applies change and replaces the site with the
// result (the API has no partial update). Every field the change does not
// touch is sent back exactly as read.
func (c *Client) ModifySite(ctx context.Context, id int, change SiteChange) (json.RawMessage, string, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	raw, err := c.Site(ctx, id)
	if err != nil {
		return nil, "", err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, "", fmt.Errorf("site %d: unexpected site object", id)
	}
	desc, err := change(m)
	if err != nil {
		return nil, "", err
	}
	if desc == "" {
		return raw, "", nil
	}
	var res json.RawMessage
	if err := c.Do(ctx, http.MethodPut, pathSites, nil, m, &res); err != nil {
		return nil, "", err
	}
	return res, desc, nil
}

// Events returns the latest events, newest first.
func (c *Client) Events(ctx context.Context, limit, siteID int) ([]WireEvent, error) {
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if siteID > 0 {
		q.Set("site_id", strconv.Itoa(siteID))
	}
	var l list[WireEvent]
	if err := c.Do(ctx, http.MethodGet, pathEvents, q, nil, &l); err != nil {
		return nil, err
	}
	return l.Data, nil
}

// Stats returns per-site counters keyed by site ID.
func (c *Client) Stats(ctx context.Context) (map[string]Counters, error) {
	var v map[string]Counters
	return v, c.Do(ctx, http.MethodGet, pathStats, nil, nil, &v)
}

// Timeseries returns the node-wide counters of the last 60 minutes.
func (c *Client) Timeseries(ctx context.Context) ([]Bucket, error) {
	var v []Bucket
	return v, c.Do(ctx, http.MethodGet, pathTimeseries, nil, nil, &v)
}

// Upstreams returns upstream health keyed by site ID.
func (c *Client) Upstreams(ctx context.Context) (map[string][]WireUpstream, error) {
	var v map[string][]WireUpstream
	return v, c.Do(ctx, http.MethodGet, pathUpstreams, nil, nil, &v)
}

// ThreatIntel returns the feed status.
func (c *Client) ThreatIntel(ctx context.Context) ([]WireFeed, error) {
	var v struct {
		Feeds []WireFeed `json:"feeds"`
	}
	return v.Feeds, c.Do(ctx, http.MethodGet, pathThreatIntel, nil, nil, &v)
}

// PurgeCache removes cached responses of siteID (0 = every site) whose
// request URI starts with prefix ("" = all).
func (c *Client) PurgeCache(ctx context.Context, siteID int, prefix string) (int, error) {
	var v struct {
		Removed int `json:"removed"`
	}
	body := map[string]any{"site_id": siteID, "prefix": prefix}
	return v.Removed, c.Do(ctx, http.MethodPost, pathCachePurge, nil, body, &v)
}

// Certs returns the certificates without their private keys.
func (c *Client) Certs(ctx context.Context) ([]WireCert, error) {
	var l list[WireCert]
	if err := c.Do(ctx, http.MethodGet, pathCerts, nil, nil, &l); err != nil {
		return nil, err
	}
	return l.Data, nil
}

// Audit returns the latest audit entries, newest first.
func (c *Client) Audit(ctx context.Context, limit int) ([]WireAudit, error) {
	var l list[WireAudit]
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if err := c.Do(ctx, http.MethodGet, pathAudit, q, nil, &l); err != nil {
		return nil, err
	}
	return l.Data, nil
}
