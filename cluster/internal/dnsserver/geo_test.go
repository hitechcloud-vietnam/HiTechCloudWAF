package dnsserver

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/miekg/dns"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
)

type geoEntry struct{ country, continent string }

// writeGeoDB writes a tiny country database mapping CIDRs to ISO country and
// continent codes, in the GeoLite2/DB-IP layout.
func writeGeoDB(t *testing.T, path string, entries map[string]geoEntry) string {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "Test-Country", RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	for cidr, e := range entries {
		_, n, _ := net.ParseCIDR(cidr)
		rec := mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(e.country)}}
		if e.continent != "" {
			rec["continent"] = mmdbtype.Map{"code": mmdbtype.String(e.continent)}
		}
		if err := w.Insert(n, rec); err != nil {
			t.Fatal(err)
		}
	}
	if path == "" {
		path = filepath.Join(t.TempDir(), "country.mmdb")
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		t.Fatal(err)
	}
	return path
}

var testGeo = map[string]geoEntry{
	"14.160.0.0/16":   {"VN", "AS"},
	"1.46.0.0/16":     {"TH", "AS"},
	"203.0.113.0/24":  {"SG", "AS"},
	"81.2.69.0/24":    {"GB", "EU"},
	"198.51.100.0/24": {"US", "NA"},
	"192.0.2.0/24":    {"JP", ""}, // no continent in the database
}

func newGeoDNS(t *testing.T, dbPath string) *Server {
	t.Helper()
	cfg := &config.DNS{
		ControllerURL: "https://controller.example:7443", Token: "dns",
		GeoIPDB: dbPath,
		Pools: map[string]config.PoolPolicy{"web": {PreferCountry: []config.CountryRule{
			{Countries: []string{"vn", "TH"}, Region: "asia"},
			{Continents: []string{"EU"}, Region: "eu"},
			{Continents: []string{"AS"}, Region: "sg"},
		}}},
		Zones: []config.Zone{{
			Name: "example.vn", NS: []string{"ns1.example.vn"}, TTL: 30, Serial: 1,
			Records: []config.Record{
				{Name: "www", Pool: "web"},
				// CIDR rules are tried before country rules.
				{Name: "cidr", Pool: "web", PreferRegion: []config.RegionRule{{CIDR: "14.160.0.0/16", Region: "eu"}}},
				// A record's own rules replace the pool's.
				{Name: "own", Pool: "web", PreferCountry: []config.CountryRule{{Countries: []string{"VN"}, Region: "eu"}}},
				{Name: "us", Pool: "web", PreferCountry: []config.CountryRule{{Countries: []string{"US"}, Region: "nowhere"}}},
			},
		}},
	}
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.SetPool("web", []api.Endpoint{
		{NodeID: "hn", Region: "asia", IPv4: "203.0.113.1", Weight: 100, Healthy: true},
		{NodeID: "sg", Region: "sg", IPv4: "203.0.113.2", Weight: 100, Healthy: true},
		{NodeID: "fra", Region: "eu", IPv4: "203.0.113.3", Weight: 100, Healthy: true},
		{NodeID: "ams", Region: "eu", IPv4: "203.0.113.4", Weight: 100, Healthy: false},
	})
	return s
}

func ecsQuery(s *Server, name, subnet string, from string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	ip, n, _ := net.ParseCIDR(subnet)
	ones, _ := n.Mask.Size()
	o.Option = append(o.Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: uint8(ones), Address: ip.To4()})
	m.Extra = append(m.Extra, o)
	return s.answer(m, net.ParseIP(from))
}

func only(t *testing.T, m *dns.Msg, want string) {
	t.Helper()
	got := ips(m)
	if len(got) != 1 || !got[want] {
		t.Fatalf("want only %s, got %v", want, m.Answer)
	}
}

func TestGeoCountryViaECS(t *testing.T) {
	s := newGeoDNS(t, writeGeoDB(t, "", testGeo))
	m := ecsQuery(s, "www.example.vn.", "14.160.10.0/24", "8.8.8.8")
	only(t, m, "203.0.113.1")
	if sc := m.IsEdns0().Option[0].(*dns.EDNS0_SUBNET).SourceScope; sc != 24 {
		t.Fatalf("routed answer scope = %d, want 24", sc)
	}
	only(t, ecsQuery(s, "www.example.vn.", "1.46.3.0/24", "8.8.8.8"), "203.0.113.1")
	// Continent rules apply when no country rule matches.
	only(t, ecsQuery(s, "www.example.vn.", "81.2.69.0/24", "8.8.8.8"), "203.0.113.3")
	only(t, ecsQuery(s, "www.example.vn.", "203.0.113.0/24", "8.8.8.8"), "203.0.113.2")
}

func TestGeoCountryViaResolverAddress(t *testing.T) {
	s := newGeoDNS(t, writeGeoDB(t, "", testGeo))
	only(t, query(s, "www.example.vn.", dns.TypeA, "14.160.1.1"), "203.0.113.1")
	only(t, query(s, "www.example.vn.", dns.TypeA, "81.2.69.10"), "203.0.113.3")
}

func TestGeoFallbacks(t *testing.T) {
	s := newGeoDNS(t, writeGeoDB(t, "", testGeo))
	// No match (US has no rule, JP has no continent, 10/8 is unknown): every
	// healthy node.
	for _, from := range []string{"198.51.100.7", "192.0.2.7", "10.1.1.1"} {
		if got := ips(query(s, "www.example.vn.", dns.TypeA, from)); len(got) != 3 {
			t.Fatalf("%s: want all healthy nodes, got %v", from, got)
		}
	}
	// A region without healthy nodes falls back to every healthy node.
	if got := ips(query(s, "us.example.vn.", dns.TypeA, "198.51.100.7")); len(got) != 3 {
		t.Fatalf("empty region: %v", got)
	}
	// CIDR rules win over GeoIP; record rules replace pool rules.
	only(t, query(s, "cidr.example.vn.", dns.TypeA, "14.160.1.1"), "203.0.113.3")
	only(t, query(s, "own.example.vn.", dns.TypeA, "14.160.1.1"), "203.0.113.3")
	if got := ips(query(s, "own.example.vn.", dns.TypeA, "81.2.69.10")); len(got) != 3 {
		t.Fatalf("record rules must not inherit pool rules: %v", got)
	}

	// Without a database the rules are ignored.
	noDB := newGeoDNS(t, "")
	if got := ips(query(noDB, "www.example.vn.", dns.TypeA, "14.160.1.1")); len(got) != 3 {
		t.Fatalf("no geoip_db: %v", got)
	}
}

func TestGeoDBReload(t *testing.T) {
	path := writeGeoDB(t, "", testGeo)
	s := newGeoDNS(t, path)
	only(t, query(s, "www.example.vn.", dns.TypeA, "14.160.1.1"), "203.0.113.1")

	// Replace the file: 14.160/16 is now in the UK.
	writeGeoDB(t, path, map[string]geoEntry{"14.160.0.0/16": {"GB", "EU"}})
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(path, future, future)
	if changed, err := s.geo.reloadIfChanged(); err != nil || !changed {
		t.Fatalf("reload: changed=%v err=%v", changed, err)
	}
	only(t, query(s, "www.example.vn.", dns.TypeA, "14.160.1.1"), "203.0.113.3")
	if changed, _ := s.geo.reloadIfChanged(); changed {
		t.Fatal("unchanged file reloaded")
	}
}

func TestGeoConfigValidation(t *testing.T) {
	db := writeGeoDB(t, "", testGeo)
	for _, rules := range [][]config.CountryRule{
		{{Countries: []string{"VNM"}, Region: "a"}},
		{{Continents: []string{"XX"}, Region: "a"}},
		{{Countries: []string{"VN"}}},
		{{Region: "a"}},
	} {
		cfg := &config.DNS{ControllerURL: "https://c:1", Token: "t", GeoIPDB: db, Zones: []config.Zone{{
			Name: "example.vn", NS: []string{"ns1.example.vn"},
			Records: []config.Record{{Name: "www", Pool: "web", PreferCountry: rules}},
		}}}
		if _, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
			t.Errorf("accepted %+v", rules)
		}
	}
	cfg := &config.DNS{ControllerURL: "https://c:1", Token: "t", GeoIPDB: filepath.Join(t.TempDir(), "missing.mmdb"),
		Zones: []config.Zone{{Name: "example.vn", NS: []string{"ns1.example.vn"}}}}
	if _, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Error("missing geoip_db accepted")
	}
}

// The shipped example must build a working server.
func TestExampleConfig(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "examples", "dns.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	db := writeGeoDB(t, "", testGeo)
	y := strings.NewReplacer(
		"token_file: /etc/hcw/secrets/dns.token", "token: d",
		"controller_ca: /etc/hcw/tls/ca.crt", "",
		"geoip_db: /etc/hcw/geoip/country.mmdb", "geoip_db: "+db,
	).Replace(string(b))
	p := filepath.Join(t.TempDir(), "dns.yaml")
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(f.DNS, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.SetPool("web", []api.Endpoint{
		{NodeID: "hn", Region: "hn", IPv4: "203.0.113.10", Healthy: true},
		{NodeID: "hcm", Region: "hcm", IPv4: "203.0.113.20", Healthy: true},
	})
	only(t, query(s, "edge.waf.hitechcloud.vn.", dns.TypeA, "1.46.1.1"), "203.0.113.20")
	only(t, query(s, "x.cdn.waf.hitechcloud.vn.", dns.TypeA, "14.160.1.1"), "203.0.113.10")
	if m := query(s, "waf.hitechcloud.vn.", dns.TypeMX, "192.0.2.1"); len(m.Answer) != 1 {
		t.Fatalf("MX = %v", m.Answer)
	}
}
