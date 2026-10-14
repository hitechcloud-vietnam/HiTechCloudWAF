// Package config loads the hcw-waf configuration file.
package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/alerts"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/proxy"
)

// Config is the node configuration. Sites and certificates are not here:
// they are managed through the API and stored in DataDir.
type Config struct {
	DataDir string `yaml:"data_dir"`
	// Bind address for site ports ("" = all interfaces).
	Bind string `yaml:"bind"`

	API struct {
		Listen    string `yaml:"listen"`
		Token     string `yaml:"token"`
		TokenFile string `yaml:"token_file"`
		// TLSCert/TLSKey; when empty a self-signed certificate is generated
		// in DataDir.
		TLSCert string `yaml:"tls_cert"`
		TLSKey  string `yaml:"tls_key"`
		// Allow limits who may reach the API and console (IPs/CIDRs).
		Allow []string `yaml:"allow"`
	} `yaml:"api"`

	BodyLimitKB    int      `yaml:"body_limit_kb"`
	TrustedProxies []string `yaml:"trusted_proxies"`
	EventsKept     int      `yaml:"events_kept"`
	EventsFile     string   `yaml:"events_file"`
	ExtraRulesFile string   `yaml:"extra_rules_file"`
	// ChallengeSecretFile signs bot/auth passes. Give every node behind the
	// same DNS name the same file. Default: <data_dir>/challenge.key,
	// generated on first start.
	ChallengeSecretFile string `yaml:"challenge_secret_file"`
	// GeoIPDB is a MaxMind-format country database (GeoLite2-Country or
	// DB-IP Country Lite). Reloaded on SIGHUP.
	GeoIPDB string      `yaml:"geoip_db"`
	Brand   proxy.Brand `yaml:"brand"`

	// ACME enables automatic certificates for sites with auto_tls.
	ACME struct {
		Enabled bool   `yaml:"enabled"`
		Email   string `yaml:"email"`
		// DirectoryURL defaults to Let's Encrypt production. Use
		// https://acme-staging-v02.api.letsencrypt.org/directory to test.
		DirectoryURL string `yaml:"directory_url"`
	} `yaml:"acme"`

	// NodeName identifies this node in alerts (default: hostname).
	NodeName string        `yaml:"node_name"`
	Alerts   alerts.Config `yaml:"alerts"`

	TrustedNets []*net.IPNet `yaml:"-"`
	APIAllow    []*net.IPNet `yaml:"-"`
	ExtraRules  string       `yaml:"-"`
}

// Load reads path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.DataDir == "" {
		c.DataDir = "/var/lib/hcw-waf"
	}
	if c.API.Listen == "" {
		c.API.Listen = "127.0.0.1:9443"
	}
	if c.API.Token == "" && c.API.TokenFile != "" {
		t, err := os.ReadFile(c.API.TokenFile)
		if err != nil {
			return nil, err
		}
		c.API.Token = strings.TrimSpace(string(t))
	}
	if len(c.API.Token) < 16 {
		return nil, fmt.Errorf("api.token (or token_file) must be at least 16 characters")
	}
	if c.BodyLimitKB == 0 {
		c.BodyLimitKB = 1024
	}
	for _, p := range c.TrustedProxies {
		n, err := model.ParseCIDR(p)
		if err != nil {
			return nil, err
		}
		c.TrustedNets = append(c.TrustedNets, n)
	}
	for _, p := range c.API.Allow {
		n, err := model.ParseCIDR(p)
		if err != nil {
			return nil, err
		}
		c.APIAllow = append(c.APIAllow, n)
	}
	if f := c.Alerts.Telegram.BotTokenFile; f != "" && c.Alerts.Telegram.BotToken == "" {
		t, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		c.Alerts.Telegram.BotToken = strings.TrimSpace(string(t))
	}
	if c.NodeName == "" {
		c.NodeName, _ = os.Hostname()
	}
	if c.ExtraRulesFile != "" {
		r, err := os.ReadFile(c.ExtraRulesFile)
		if err != nil {
			return nil, err
		}
		c.ExtraRules = string(r)
	}
	return &c, nil
}
