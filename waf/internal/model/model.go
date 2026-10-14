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
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
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

	RateLimit RateLimit `json:"rate_limit"`
	// IPAllow, when non-empty, only admits these CIDRs. IPDeny always blocks.
	IPAllow []string `json:"ip_allow"`
	IPDeny  []string `json:"ip_deny"`

	// UpstreamHost overrides the Host header sent upstream (default: keep).
	UpstreamHost string `json:"upstream_host"`
	// UpstreamInsecure skips certificate checks of https upstreams.
	UpstreamInsecure bool `json:"upstream_insecure"`
	// RedirectHTTPS sends plain-HTTP clients to the https port.
	RedirectHTTPS bool `json:"redirect_https"`

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
	if hasTLS && s.CertID == 0 {
		return errors.New("an _ssl port needs cert_id")
	}
	if len(s.Upstreams) == 0 {
		return errors.New("upstreams is required")
	}
	for _, u := range s.Upstreams {
		pu, err := url.Parse(u)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" || (pu.Path != "" && pu.Path != "/") {
			return fmt.Errorf("invalid upstream %q (use http(s)://host[:port])", u)
		}
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
	if s.Name == "" {
		s.Name = s.ServerNames[0]
	}
	return nil
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
