// Package model defines the objects managed through the HiTechCloud WAF
// management API, and their validation.
package model

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Protection modes of a site.
const (
	ModeBlock   = "block"   // detect and block
	ModeMonitor = "monitor" // detect and log only
	ModeOff     = "off"     // pure reverse proxy
)

// RateLimit throttles one client IP on one site.
type RateLimit struct {
	// Requests allowed per WindowSec. 0 disables rate limiting.
	Requests  int `json:"requests"`
	WindowSec int `json:"window_sec"`
	// BlockSec is how long a client stays blocked after exceeding the limit.
	BlockSec int `json:"block_sec"`
}

// BotChallenge makes browsers solve a JavaScript proof-of-work before they
// reach the site. Scripts and simple bots without a JS engine fail it.
type BotChallenge struct {
	Enabled bool `json:"enabled"`
	// TTLSec is how long a solved challenge stays valid (default 3600).
	TTLSec int `json:"ttl_sec"`
	// Difficulty in leading zero bits of SHA-256 (default 16 ≈ 65k hashes,
	// under a second on phones; each +1 doubles the work).
	Difficulty int `json:"difficulty"`
	// ExcludePaths are path prefixes served without challenge (APIs, webhooks).
	ExcludePaths []string `json:"exclude_paths"`
}

// AuthChallenge protects a site with a shared password.
type AuthChallenge struct {
	Enabled bool `json:"enabled"`
	// Password is write-only: it is hashed into PasswordHash on save.
	Password     string   `json:"password,omitempty"`
	PasswordHash string   `json:"password_hash"`
	TTLSec       int      `json:"ttl_sec"`
	ExcludePaths []string `json:"exclude_paths"`
}

// DynamicProtection re-encodes HTML pages and JavaScript files on every
// response so that scrapers without a JavaScript engine get nothing useful.
type DynamicProtection struct {
	HTML bool `json:"html"`
	JS   bool `json:"js"`
	// Paths limits protection to these path prefixes (empty = whole site).
	Paths []string `json:"paths"`
}

// CacheConfig keeps copies of static upstream responses in the node's
// memory so repeated requests do not reach the origin. Security checks
// (ACL, rate limits, challenges, WAF) still run on every request.
type CacheConfig struct {
	Enabled bool `json:"enabled"`
	// TTLSec is how long an object is kept (default 300, at most 86400). A
	// shorter upstream Cache-Control s-maxage/max-age wins.
	TTLSec int `json:"ttl_sec"`
	// MaxObjectKB is the largest response body stored (default 1024).
	MaxObjectKB int `json:"max_object_kb"`
	// Paths, when set, caches everything under these path prefixes and
	// ignores Extensions. When empty, requests are cached by extension.
	Paths []string `json:"paths"`
	// Extensions of cacheable paths, e.g. ".css" (default: common static
	// files, see DefaultCacheExtensions).
	Extensions []string `json:"extensions"`
}

// DefaultCacheExtensions are cached when cache.extensions is empty.
var DefaultCacheExtensions = []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".map"}

func (c *CacheConfig) normalize() error {
	if c.TTLSec == 0 {
		c.TTLSec = 300
	}
	if c.MaxObjectKB == 0 {
		c.MaxObjectKB = 1024
	}
	if c.TTLSec < 1 || c.TTLSec > 86400 {
		return errors.New("cache.ttl_sec must be 1..86400")
	}
	if c.MaxObjectKB < 1 || c.MaxObjectKB > 100*1024 {
		return errors.New("cache.max_object_kb must be 1..102400")
	}
	if err := checkPaths(c.Paths); err != nil {
		return err
	}
	if len(c.Extensions) == 0 {
		c.Extensions = append([]string(nil), DefaultCacheExtensions...)
	}
	for i, x := range c.Extensions {
		x = strings.ToLower(strings.TrimSpace(x))
		if !strings.HasPrefix(x, ".") {
			x = "." + x
		}
		if len(x) < 2 || len(x) > 16 || strings.ContainsAny(x[1:], "./?#* ") {
			return fmt.Errorf("invalid cache extension %q (use e.g. .css)", c.Extensions[i])
		}
		c.Extensions[i] = x
	}
	return nil
}

// HealthCheck actively probes upstreams; unhealthy ones leave the rotation.
type HealthCheck struct {
	// Path to request, e.g. /healthz (empty = disabled).
	Path        string `json:"path"`
	IntervalSec int    `json:"interval_sec"` // default 10
	TimeoutSec  int    `json:"timeout_sec"`  // default 3
	// Unhealthy consecutive failures take an upstream out (default 3);
	// Healthy consecutive successes bring it back (default 2).
	Unhealthy int `json:"unhealthy"`
	Healthy   int `json:"healthy"`
}

func (h *HealthCheck) normalize() error {
	if h.Path == "" {
		return nil
	}
	if !strings.HasPrefix(h.Path, "/") {
		return errors.New("health_check.path must start with /")
	}
	if h.IntervalSec == 0 {
		h.IntervalSec = 10
	}
	if h.TimeoutSec == 0 {
		h.TimeoutSec = 3
	}
	if h.Unhealthy == 0 {
		h.Unhealthy = 3
	}
	if h.Healthy == 0 {
		h.Healthy = 2
	}
	if h.IntervalSec < 1 || h.IntervalSec > 3600 || h.TimeoutSec < 1 || h.TimeoutSec > 60 || h.Unhealthy < 1 || h.Unhealthy > 100 || h.Healthy < 1 || h.Healthy > 100 {
		return errors.New("health_check values out of range")
	}
	return nil
}

// Rule actions.
const (
	RuleAllow     = "allow"      // whitelist: skip rate limits, challenges and WAF
	RuleDeny      = "deny"       // block with 403
	RuleSkipWAF   = "skip_waf"   // skip OWASP CRS inspection only
	RuleRateLimit = "rate_limit" // extra per-path rate limit
)

// PathRule refines protection for part of a site. Rules are evaluated in
// order; allow and deny stop the evaluation.
type PathRule struct {
	Path string `json:"path"`
	// Exact matches the whole path instead of a prefix.
	Exact bool `json:"exact"`
	// Methods limits the rule to these HTTP methods (empty = all).
	Methods []string `json:"methods"`
	// IPs limits the rule to these client networks (empty = everyone).
	IPs       []string  `json:"ips"`
	Action    string    `json:"action"`
	RateLimit RateLimit `json:"rate_limit"`
	Comment   string    `json:"comment"`
}

func (r *PathRule) normalize() error {
	if !strings.HasPrefix(r.Path, "/") {
		return fmt.Errorf("rule path %q must start with /", r.Path)
	}
	switch r.Action {
	case RuleAllow, RuleDeny, RuleSkipWAF:
	case RuleRateLimit:
		rl := &r.RateLimit
		if rl.Requests <= 0 {
			return fmt.Errorf("rule %s: rate_limit.requests must be > 0", r.Path)
		}
		if rl.WindowSec <= 0 {
			rl.WindowSec = 60
		}
		if rl.BlockSec <= 0 {
			rl.BlockSec = 300
		}
	default:
		return fmt.Errorf("rule %s: action must be allow, deny, skip_waf or rate_limit", r.Path)
	}
	for i, m := range r.Methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" || strings.ContainsAny(m, " /") {
			return fmt.Errorf("rule %s: invalid method %q", r.Path, m)
		}
		r.Methods[i] = m
	}
	for i, c := range r.IPs {
		n, err := ParseCIDR(c)
		if err != nil {
			return err
		}
		r.IPs[i] = n.String()
	}
	return nil
}

// Site is one protected application.
type Site struct {
	ID          int      `json:"id"`
	Name        string   `json:"name"`
	ServerNames []string `json:"server_names"`
	// Ports to listen on: "80", "8080", "443_ssl".
	Ports     []string `json:"ports"`
	Upstreams []string `json:"upstreams"`
	CertID    int      `json:"cert_id"`
	Mode      string   `json:"mode"`
	// Paranoia is the OWASP CRS paranoia level, 1 (default) to 4.
	Paranoia int `json:"paranoia"`
	// AnomalyThreshold is the CRS inbound anomaly score that blocks (default 5).
	AnomalyThreshold int `json:"anomaly_threshold"`
	// DisabledRules are CRS rule IDs removed for this site (false positives).
	DisabledRules []int `json:"disabled_rules"`

	RateLimit RateLimit         `json:"rate_limit"`
	Bot       BotChallenge      `json:"bot_challenge"`
	Dynamic   DynamicProtection `json:"dynamic_protection"`
	Rules     []PathRule        `json:"rules"`
	Health    HealthCheck       `json:"health_check"`
	Auth      AuthChallenge     `json:"auth"`
	Cache     CacheConfig       `json:"cache"`
	// Compress gzips compressible responses (text, JSON, JS, XML, SVG) for
	// clients that accept it, when the upstream did not compress them.
	Compress bool `json:"compress"`
	// IPAllow, when non-empty, only admits these CIDRs. IPDeny always blocks.
	IPAllow []string `json:"ip_allow"`
	IPDeny  []string `json:"ip_deny"`
	// CountryAllow, when non-empty, only admits these ISO country codes;
	// CountryDeny always blocks. Needs geoip_db in the node configuration.
	CountryAllow []string `json:"country_allow"`
	CountryDeny  []string `json:"country_deny"`

	// UpstreamHost overrides the Host header sent upstream (default: keep).
	UpstreamHost string `json:"upstream_host"`
	// UpstreamInsecure skips certificate checks of https upstreams.
	UpstreamInsecure bool `json:"upstream_insecure"`
	// LB is the balancing strategy: round_robin (default), weighted,
	// least_conn, ip_hash or random. Upstreams may end in " weight=N".
	LB string `json:"lb"`
	// Sticky pins a browser to one upstream with a signed cookie
	// (StickyCookie, default hcw_srv; StickyTTLSec 0 = browser session).
	Sticky       bool   `json:"sticky"`
	StickyCookie string `json:"sticky_cookie"`
	StickyTTLSec int    `json:"sticky_ttl_sec"`
	// RequestHeaders / ResponseHeaders rewrite headers to and from upstreams;
	// HideServerHeaders strips Server, X-Powered-By and similar banners.
	RequestHeaders    []HeaderRule `json:"request_headers"`
	ResponseHeaders   []HeaderRule `json:"response_headers"`
	HideServerHeaders bool         `json:"hide_server_headers"`
	// RedirectHTTPS sends plain-HTTP clients to the https port.
	RedirectHTTPS bool `json:"redirect_https"`
	// AutoTLS obtains and renews certificates from Let's Encrypt (ACME) for
	// the server names; cert_id is then not needed.
	AutoTLS bool `json:"auto_tls"`
	// HSTS adds Strict-Transport-Security to HTTPS responses.
	HSTS bool `json:"hsts"`
	// CustomRules are extra SecLang rules for this site (after the CRS).
	CustomRules string `json:"custom_rules"`

	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Cert is a TLS certificate and key in PEM.
type Cert struct {
	ID      int      `json:"id"`
	Domains []string `json:"domains"`
	Crt     string   `json:"crt"`
	Key     string   `json:"key"`

	// Filled from the certificate.
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var hostRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ParsePort parses "443_ssl" into (443, true).
func ParsePort(p string) (int, bool, error) {
	tlsOn := strings.HasSuffix(p, "_ssl")
	n, err := strconv.Atoi(strings.TrimSuffix(p, "_ssl"))
	if err != nil || n < 1 || n > 65535 {
		return 0, false, fmt.Errorf("invalid port %q (use e.g. 80 or 443_ssl)", p)
	}
	return n, tlsOn, nil
}

// Normalize fills defaults and validates s.
func (s *Site) Normalize() error {
	if len(s.ServerNames) == 0 {
		return errors.New("server_names is required")
	}
	for i, n := range s.ServerNames {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n != "_" && !hostRe.MatchString(n) {
			return fmt.Errorf("invalid server name %q", n)
		}
		s.ServerNames[i] = n
	}
	if len(s.Ports) == 0 {
		s.Ports = []string{"80"}
	}
	hasTLS := false
	for _, p := range s.Ports {
		_, t, err := ParsePort(p)
		if err != nil {
			return err
		}
		hasTLS = hasTLS || t
	}
	if hasTLS && s.CertID == 0 && !s.AutoTLS {
		return errors.New("an _ssl port needs cert_id or auto_tls")
	}
	if s.AutoTLS {
		for _, n := range s.ServerNames {
			if n == "_" || strings.HasPrefix(n, "*.") {
				return fmt.Errorf("auto_tls cannot issue certificates for %q (no wildcards or catch-all)", n)
			}
		}
	}
	if err := checkCustomRules(s.CustomRules); err != nil {
		return err
	}
	if err := s.normalizeUpstreams(); err != nil {
		return err
	}
	if err := s.normalizeHeaders(); err != nil {
		return err
	}
	switch s.Mode {
	case "":
		s.Mode = ModeBlock
	case ModeBlock, ModeMonitor, ModeOff:
	default:
		return fmt.Errorf("mode must be %s, %s or %s", ModeBlock, ModeMonitor, ModeOff)
	}
	if s.Paranoia == 0 {
		s.Paranoia = 1
	}
	if s.Paranoia < 1 || s.Paranoia > 4 {
		return errors.New("paranoia must be 1..4")
	}
	if s.AnomalyThreshold == 0 {
		s.AnomalyThreshold = 5
	}
	if s.AnomalyThreshold < 1 || s.AnomalyThreshold > 1000 {
		return errors.New("anomaly_threshold must be 1..1000")
	}
	for _, r := range s.DisabledRules {
		if r < 900000 || r > 999999 {
			return fmt.Errorf("disabled rule %d is not a CRS rule id", r)
		}
	}
	rl := &s.RateLimit
	if rl.Requests < 0 || rl.WindowSec < 0 || rl.BlockSec < 0 {
		return errors.New("rate_limit values must be >= 0")
	}
	if rl.Requests > 0 {
		if rl.WindowSec == 0 {
			rl.WindowSec = 60
		}
		if rl.BlockSec == 0 {
			rl.BlockSec = 60
		}
	}
	for _, list := range [][]string{s.IPAllow, s.IPDeny} {
		for i, c := range list {
			n, err := ParseCIDR(c)
			if err != nil {
				return err
			}
			list[i] = n.String()
		}
	}
	for _, list := range [][]string{s.CountryAllow, s.CountryDeny} {
		for i, c := range list {
			c = strings.ToUpper(strings.TrimSpace(c))
			if len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
				return fmt.Errorf("invalid country code %q (use ISO 3166-1 alpha-2, e.g. VN)", c)
			}
			list[i] = c
		}
	}
	if s.Name == "" {
		s.Name = s.ServerNames[0]
	}
	if err := s.Health.normalize(); err != nil {
		return err
	}
	if len(s.Rules) > 200 {
		return errors.New("at most 200 rules per site")
	}
	for i := range s.Rules {
		if err := s.Rules[i].normalize(); err != nil {
			return err
		}
	}
	if err := checkPaths(s.Dynamic.Paths); err != nil {
		return err
	}
	if err := s.Bot.normalize(); err != nil {
		return err
	}
	if err := s.Cache.normalize(); err != nil {
		return err
	}
	return s.Auth.normalize()
}

// customRuleIDs keeps operator rules apart from the CRS (900000-999999) and
// engine-internal IDs (100000-199999).
var ruleIDRe = regexp.MustCompile(`(?i)\bid\s*:\s*'?(\d+)`)

var allowedDirectives = map[string]bool{
	"secrule": true, "secaction": true, "secmarker": true,
	"secruleremovebyid": true, "secruleremovebytag": true, "secruleremovebymsg": true,
	"secruleupdatetargetbyid": true, "secruleupdatetargetbytag": true, "secruleupdatetargetbymsg": true,
	"secruleupdateactionbyid": true,
}

var fileOpRe = regexp.MustCompile(`(?i)@(pmfromfile|pmf|ipmatchfromfile|ipmatchf|inspectfile|validateschema|validatedtd|rbl)\b`)

func checkCustomRules(rules string) error {
	if len(rules) > 64<<10 {
		return errors.New("custom_rules is larger than 64 KiB")
	}
	// Rules come over the API and are replicated between nodes: only rule
	// directives are accepted (no logs, uploads, data dirs or includes that
	// touch the local disk) and no operator may read files or the network.
	if m := fileOpRe.FindString(rules); m != "" {
		return fmt.Errorf("custom_rules may not use %s", m)
	}
	for _, line := range strings.Split(strings.ReplaceAll(rules, "\\\n", " "), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		d, _, _ := strings.Cut(l, " ")
		d, _, _ = strings.Cut(d, "\t")
		if !allowedDirectives[strings.ToLower(d)] {
			return fmt.Errorf("custom_rules may not use the %s directive", d)
		}
	}
	for _, m := range ruleIDRe.FindAllStringSubmatch(rules, -1) {
		id, _ := strconv.Atoi(m[1])
		if id < 1 || id >= 100000 {
			return fmt.Errorf("custom rule id %d must be between 1 and 99999", id)
		}
	}
	return nil
}

func checkPaths(ps []string) error {
	for _, p := range ps {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("exclude path %q must start with /", p)
		}
	}
	return nil
}

func (b *BotChallenge) normalize() error {
	if b.TTLSec == 0 {
		b.TTLSec = 3600
	}
	if b.Difficulty == 0 {
		b.Difficulty = 16
	}
	if b.TTLSec < 60 || b.TTLSec > 30*86400 {
		return errors.New("bot_challenge.ttl_sec must be 60..2592000")
	}
	if b.Difficulty < 8 || b.Difficulty > 24 {
		return errors.New("bot_challenge.difficulty must be 8..24")
	}
	return checkPaths(b.ExcludePaths)
}

func (a *AuthChallenge) normalize() error {
	if a.TTLSec == 0 {
		a.TTLSec = 8 * 3600
	}
	if a.TTLSec < 60 || a.TTLSec > 30*86400 {
		return errors.New("auth.ttl_sec must be 60..2592000")
	}
	if a.Password != "" {
		if len(a.Password) < 8 || len(a.Password) > 72 {
			return errors.New("auth.password must be 8..72 characters")
		}
		h, err := bcrypt.GenerateFromPassword([]byte(a.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		a.PasswordHash, a.Password = string(h), ""
	}
	if a.PasswordHash != "" {
		if _, err := bcrypt.Cost([]byte(a.PasswordHash)); err != nil {
			return errors.New("auth.password_hash is not a bcrypt hash")
		}
	}
	if a.Enabled && a.PasswordHash == "" {
		return errors.New("auth.enabled needs auth.password")
	}
	return checkPaths(a.ExcludePaths)
}

// ParseCIDR accepts a CIDR or a single address.
func ParseCIDR(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP/CIDR %q", s)
		}
		bits := 128
		if ip.To4() != nil {
			ip, bits = ip.To4(), 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("invalid IP/CIDR %q", s)
	}
	return n, nil
}

// Normalize validates the key pair and fills metadata.
func (c *Cert) Normalize() error {
	pair, err := tls.X509KeyPair([]byte(c.Crt), []byte(c.Key))
	if err != nil {
		return fmt.Errorf("invalid certificate/key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	c.Issuer = leaf.Issuer.CommonName
	c.NotAfter = leaf.NotAfter
	if len(c.Domains) == 0 {
		c.Domains = append([]string(nil), leaf.DNSNames...)
		if len(c.Domains) == 0 && leaf.Subject.CommonName != "" {
			c.Domains = []string{leaf.Subject.CommonName}
		}
	}
	if len(c.Domains) == 0 {
		return errors.New("domains is required")
	}
	return nil
}

// KeyPair returns the parsed certificate.
func (c *Cert) KeyPair() (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(c.Crt), []byte(c.Key))
}

// IsPEM is a cheap check used by tests.
func IsPEM(s string) bool { b, _ := pem.Decode([]byte(s)); return b != nil }
