// Package config loads the YAML configuration of every hcw role.
package config

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/auth"
)

// Duration accepts Go duration strings ("10s", "1m") in YAML.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

func orDefault(d Duration, def time.Duration) time.Duration {
	if d.Duration <= 0 {
		return def
	}
	return d.Duration
}

// Engine describes how to reach the management API of one WAF engine
// instance and which resources are replicated across the cluster.
type Engine struct {
	// BaseURL of the engine console, e.g. https://127.0.0.1:9443
	BaseURL   string `yaml:"base_url"`
	Token     string `yaml:"token"`
	TokenFile string `yaml:"token_file"`
	// TokenHeader is the header carrying the API token.
	TokenHeader string `yaml:"token_header"`
	// CAFile pins the CA of the engine console certificate.
	CAFile string `yaml:"ca_file"`
	// InsecureSkipVerify is only honoured for loopback base URLs.
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify"`
	HealthPath         string   `yaml:"health_path"`
	Timeout            Duration `yaml:"timeout"`

	Resources []Resource `yaml:"resources"`
}

// Resource is one replicated collection of the engine API.
type Resource struct {
	Name string `yaml:"name"`
	// Path of the collection, e.g. /api/open/site
	Path string `yaml:"path"`
	// ListQuery is appended to GET Path, e.g. "page=1&page_size=1000".
	ListQuery string `yaml:"list_query"`
	// ItemsPath is the dotted path of the item array in the list response,
	// e.g. "data.data".
	ItemsPath string `yaml:"items_path"`
	IDField   string `yaml:"id_field"`
	// KeyFields identify the same object on different nodes.
	KeyFields []string `yaml:"key_fields"`
	// IgnoreFields are dropped before comparing and writing (server-managed
	// fields such as timestamps and counters).
	IgnoreFields []string `yaml:"ignore_fields"`
	// Refs maps a field holding the ID of another resource to that
	// resource's name, so IDs can be translated between nodes.
	Refs         map[string]string `yaml:"refs"`
	UpdateMethod string            `yaml:"update_method"`
	// DeleteMode is "body_ids" (DELETE Path with {"ids":[id]}) or "path"
	// (DELETE Path/{id}).
	DeleteMode string `yaml:"delete_mode"`
	// Prune deletes objects that exist on the node but not on the primary.
	Prune bool `yaml:"prune"`
}

func (e *Engine) applyDefaults() error {
	if e.TokenHeader == "" {
		e.TokenHeader = "X-SLCE-API-TOKEN"
	}
	if e.HealthPath == "" {
		e.HealthPath = "/api/open/health"
	}
	e.Timeout.Duration = orDefault(e.Timeout, 15*time.Second)
	t, err := auth.Resolve(e.Token, e.TokenFile)
	if err != nil {
		return err
	}
	e.Token = t
	for i := range e.Resources {
		r := &e.Resources[i]
		if r.Name == "" || r.Path == "" {
			return fmt.Errorf("engine resource #%d needs name and path", i)
		}
		if r.ItemsPath == "" {
			r.ItemsPath = "data.data"
		}
		if r.IDField == "" {
			r.IDField = "id"
		}
		if len(r.KeyFields) == 0 {
			return fmt.Errorf("engine resource %s needs key_fields", r.Name)
		}
		if r.UpdateMethod == "" {
			r.UpdateMethod = "PUT"
		}
		if r.DeleteMode == "" {
			r.DeleteMode = "body_ids"
		}
		if r.DeleteMode != "body_ids" && r.DeleteMode != "path" {
			return fmt.Errorf("engine resource %s: delete_mode must be body_ids or path", r.Name)
		}
	}
	return nil
}

// Controller is the control-plane configuration.
type Controller struct {
	Listen    string `yaml:"listen"`
	TLSCert   string `yaml:"tls_cert"`
	TLSKey    string `yaml:"tls_key"`
	StateFile string `yaml:"state_file"`

	AdminToken     string `yaml:"admin_token"`
	AdminTokenFile string `yaml:"admin_token_file"`
	// NodeToken is shared by agents to register and fetch configuration.
	NodeToken     string `yaml:"node_token"`
	NodeTokenFile string `yaml:"node_token_file"`
	// DNSToken lets DNS servers read pool endpoints and static records only.
	DNSToken     string `yaml:"dns_token"`
	DNSTokenFile string `yaml:"dns_token_file"`
	// DNSRecordsFile persists the static DNS records managed through the
	// API. Defaults to dns-records.json next to state_file.
	DNSRecordsFile string `yaml:"dns_records_file"`

	HeartbeatTimeout Duration `yaml:"heartbeat_timeout"`
	ProbeInterval    Duration `yaml:"probe_interval"`
	ProbeTimeout     Duration `yaml:"probe_timeout"`
	// ProbeInsecure skips TLS verification for node probes (nodes usually
	// answer probes by IP, so names do not match).
	ProbeInsecure bool `yaml:"probe_insecure"`
	// AllowLoopbackNodes accepts node addresses on loopback, link-local and
	// similar ranges (labs only); probes refuse to dial them otherwise.
	AllowLoopbackNodes bool `yaml:"allow_loopback_nodes"`
	// AllowAddressChange lets a node change its registered IPv4/IPv6 by
	// heartbeat. Off by default: since every node shares the node token, a
	// changed address must be accepted by an admin (delete the node, it then
	// registers again).
	AllowAddressChange bool `yaml:"allow_address_change"`
	// ForgetAfter removes nodes that have been silent this long (0 = never).
	ForgetAfter Duration `yaml:"forget_after"`

	// Primary is the engine whose configuration is replicated to all nodes.
	// Leave base_url empty to disable configuration replication.
	Primary      Engine   `yaml:"primary"`
	SyncInterval Duration `yaml:"sync_interval"`

	Brand Brand `yaml:"brand"`
}

// Brand customises the controller dashboard (white label).
type Brand struct {
	Name         string `yaml:"name"`
	PrimaryColor string `yaml:"primary_color"`
	LogoURL      string `yaml:"logo_url"`
	SupportURL   string `yaml:"support_url"`
}

// Agent is the node configuration.
type Agent struct {
	ControllerURL string `yaml:"controller_url"`
	ControllerCA  string `yaml:"controller_ca"`
	NodeToken     string `yaml:"node_token"`
	NodeTokenFile string `yaml:"node_token_file"`

	ID       string            `yaml:"id"`
	Name     string            `yaml:"name"`
	Region   string            `yaml:"region"`
	Pools    []string          `yaml:"pools"`
	IPv4     string            `yaml:"ipv4"`
	IPv6     string            `yaml:"ipv6"`
	Weight   int               `yaml:"weight"`
	Labels   map[string]string `yaml:"labels"`
	ProbeURL string            `yaml:"probe_url"`
	DataDir  string            `yaml:"data_dir"`

	Interval Duration `yaml:"interval"`
	// Engine is the local WAF engine. Its resources list is not needed: the
	// agent applies the resource definitions of the snapshot it receives
	// against the controller's resource list, so only connection settings
	// matter here. When resources are given they override the defaults.
	Engine Engine `yaml:"engine"`
	// ApplyConfig enables replicating the primary configuration locally.
	ApplyConfig bool `yaml:"apply_config"`
}

// DNS is the authoritative DNS server configuration.
type DNS struct {
	Listen        string   `yaml:"listen"`
	ControllerURL string   `yaml:"controller_url"`
	ControllerCA  string   `yaml:"controller_ca"`
	Token         string   `yaml:"token"`
	TokenFile     string   `yaml:"token_file"`
	Refresh       Duration `yaml:"refresh"`
	// GeoIPDB is an optional MaxMind/DB-IP country database (.mmdb) used by
	// prefer_country rules. It is reloaded when the file changes.
	GeoIPDB string `yaml:"geoip_db"`
	// Pools holds defaults applied to every record of a pool.
	Pools map[string]PoolPolicy `yaml:"pools"`
	Zones []Zone                `yaml:"zones"`
}

// PoolPolicy is the routing policy shared by the records of one pool.
type PoolPolicy struct {
	// PreferCountry applies to records of the pool without their own rules.
	PreferCountry []CountryRule `yaml:"prefer_country"`
}

// Zone is one authoritative zone.
type Zone struct {
	Name       string   `yaml:"name"`
	NS         []string `yaml:"ns"`
	Hostmaster string   `yaml:"hostmaster"`
	TTL        uint32   `yaml:"ttl"`
	Serial     uint32   `yaml:"serial"`
	Records    []Record `yaml:"records"`
}

// Record is either static (Type + Value) or dynamic (Pool). Static records
// can also be managed through the controller API.
type Record struct {
	// Name is relative to the zone: "@" for the apex, "*.app" for a
	// wildcard.
	Name string `yaml:"name"`
	// Type is A, AAAA, CNAME, TXT, MX, NS, SRV or CAA (A/AAAA for pools).
	Type string `yaml:"type"`
	// Value is the static data in zone file syntax, e.g. MX
	// "10 mail.example.com.", SRV "10 60 5060 sip.example.com.", CAA
	// `0 issue "letsencrypt.org"`. Names without a trailing dot are relative
	// to the zone.
	Value string `yaml:"value"`
	TTL   uint32 `yaml:"ttl"`

	// Pool makes the record dynamic: A/AAAA answers are healthy nodes of the
	// pool.
	Pool string `yaml:"pool"`
	// MaxAnswers limits how many addresses are returned (weighted random).
	MaxAnswers int `yaml:"max_answers"`
	// PreferRegion maps client subnets (CIDR, matched against EDNS client
	// subnet or the resolver address) to node regions.
	PreferRegion []RegionRule `yaml:"prefer_region"`
	// PreferCountry maps the client country or continent (GeoIP of the EDNS
	// client subnet or the resolver address) to node regions. It is tried
	// after prefer_region and needs dns.geoip_db.
	PreferCountry []CountryRule `yaml:"prefer_country"`
	// FailOpen answers with every node of the pool when none is healthy,
	// instead of an empty answer.
	FailOpen bool `yaml:"fail_open"`
}

// RegionRule routes clients from CIDR to Region.
type RegionRule struct {
	CIDR   string `yaml:"cidr"`
	Region string `yaml:"region"`
}

// CountryRule routes clients located in Countries (ISO 3166-1 alpha-2,
// e.g. VN) or Continents (AF, AN, AS, EU, NA, OC, SA) to Region. Country
// matches win over continent matches.
type CountryRule struct {
	Countries  []string `yaml:"countries"`
	Continents []string `yaml:"continents"`
	Region     string   `yaml:"region"`
}

// File is the top level configuration file.
type File struct {
	Controller *Controller `yaml:"controller"`
	Agent      *Agent      `yaml:"agent"`
	DNS        *DNS        `yaml:"dns"`
}

// Load reads and validates path.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	dec := yaml.NewDecoder(bytesReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := f.normalize(); err != nil {
		return nil, err
	}
	return &f, nil
}

func (f *File) normalize() error {
	if c := f.Controller; c != nil {
		if c.Listen == "" {
			c.Listen = ":7443"
		}
		if c.StateFile == "" {
			c.StateFile = "/var/lib/hcw/controller-state.json"
		}
		var err error
		if c.AdminToken, err = auth.Resolve(c.AdminToken, c.AdminTokenFile); err != nil {
			return err
		}
		if c.NodeToken, err = auth.Resolve(c.NodeToken, c.NodeTokenFile); err != nil {
			return err
		}
		if c.DNSToken, err = auth.Resolve(c.DNSToken, c.DNSTokenFile); err != nil {
			return err
		}
		if c.AdminToken == "" || c.NodeToken == "" {
			return fmt.Errorf("controller: admin_token and node_token are required")
		}
		c.HeartbeatTimeout.Duration = orDefault(c.HeartbeatTimeout, 30*time.Second)
		c.ProbeInterval.Duration = orDefault(c.ProbeInterval, 10*time.Second)
		c.ProbeTimeout.Duration = orDefault(c.ProbeTimeout, 3*time.Second)
		c.SyncInterval.Duration = orDefault(c.SyncInterval, 30*time.Second)
		if c.Brand.Name == "" {
			c.Brand.Name = "HiTechCloud WAF"
		}
		if c.Brand.PrimaryColor == "" {
			c.Brand.PrimaryColor = "#1D4ED8"
		}
		if c.Primary.BaseURL != "" {
			if err := c.Primary.applyDefaults(); err != nil {
				return fmt.Errorf("controller.primary: %w", err)
			}
		}
	}
	if a := f.Agent; a != nil {
		var err error
		if a.NodeToken, err = auth.Resolve(a.NodeToken, a.NodeTokenFile); err != nil {
			return err
		}
		if a.ControllerURL == "" || a.NodeToken == "" {
			return fmt.Errorf("agent: controller_url and node_token are required")
		}
		if a.DataDir == "" {
			a.DataDir = "/var/lib/hcw"
		}
		a.Interval.Duration = orDefault(a.Interval, 10*time.Second)
		if a.Engine.BaseURL != "" {
			if err := a.Engine.applyDefaults(); err != nil {
				return fmt.Errorf("agent.engine: %w", err)
			}
		}
		if a.ApplyConfig && a.Engine.BaseURL == "" {
			return fmt.Errorf("agent: apply_config needs engine.base_url")
		}
	}
	if d := f.DNS; d != nil {
		var err error
		if d.Token, err = auth.Resolve(d.Token, d.TokenFile); err != nil {
			return err
		}
		if d.Listen == "" {
			d.Listen = ":53"
		}
		if d.ControllerURL == "" || d.Token == "" {
			return fmt.Errorf("dns: controller_url and token are required")
		}
		d.Refresh.Duration = orDefault(d.Refresh, 5*time.Second)
		if len(d.Zones) == 0 {
			return fmt.Errorf("dns: at least one zone is required")
		}
		for i := range d.Zones {
			z := &d.Zones[i]
			if z.Name == "" || len(z.NS) == 0 {
				return fmt.Errorf("dns zone #%d needs name and ns", i)
			}
			if z.TTL == 0 {
				z.TTL = 30
			}
			if z.Serial == 0 {
				z.Serial = uint32(time.Now().Unix())
			}
			if z.Hostmaster == "" {
				z.Hostmaster = "hostmaster." + z.Name
			}
		}
	}
	return nil
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
