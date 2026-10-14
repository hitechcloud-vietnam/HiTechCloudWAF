package dnsserver

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
)

var continents = map[string]bool{"AF": true, "AN": true, "AS": true, "EU": true, "NA": true, "OC": true, "SA": true}

// countryRule is a compiled config.CountryRule.
type countryRule struct {
	countries  map[string]bool
	continents map[string]bool
	region     string
}

func compileCountryRules(in []config.CountryRule) ([]countryRule, error) {
	out := make([]countryRule, 0, len(in))
	for _, c := range in {
		r := countryRule{countries: map[string]bool{}, continents: map[string]bool{}, region: c.Region}
		if c.Region == "" {
			return nil, fmt.Errorf("prefer_country rule needs a region")
		}
		for _, cc := range c.Countries {
			cc = strings.ToUpper(strings.TrimSpace(cc))
			if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
				return nil, fmt.Errorf("invalid country code %q (want ISO 3166-1 alpha-2, e.g. VN)", cc)
			}
			r.countries[cc] = true
		}
		for _, ct := range c.Continents {
			ct = strings.ToUpper(strings.TrimSpace(ct))
			if !continents[ct] {
				return nil, fmt.Errorf("invalid continent code %q (want AF, AN, AS, EU, NA, OC or SA)", ct)
			}
			r.continents[ct] = true
		}
		if len(r.countries) == 0 && len(r.continents) == 0 {
			return nil, fmt.Errorf("prefer_country rule for region %s needs countries or continents", c.Region)
		}
		out = append(out, r)
	}
	return out, nil
}

// countryRegion returns the region of the first rule listing country.
func countryRegion(rules []countryRule, country string) string {
	for _, r := range rules {
		if country != "" && r.countries[country] {
			return r.region
		}
	}
	return ""
}

// continentRegion returns the region of the first rule listing continent.
func continentRegion(rules []countryRule, continent string) string {
	for _, r := range rules {
		if continent != "" && r.continents[continent] {
			return r.region
		}
	}
	return ""
}

// geoDB is a country database (GeoLite2-Country, DB-IP Country Lite, ...).
// It is read into memory, so a reload never unmaps data that a concurrent
// lookup still uses.
type geoDB struct {
	path string
	r    atomic.Pointer[maxminddb.Reader]

	mu    sync.Mutex // serialises reloads
	mtime time.Time
	size  int64
}

type geoRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	// Some databases only fill registered_country.
	Registered struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
}

func openGeoDB(path string) (*geoDB, error) {
	g := &geoDB{path: path}
	if _, err := g.reloadIfChanged(); err != nil {
		return nil, err
	}
	return g, nil
}

// reloadIfChanged reopens the database when the file was replaced (e.g. by a
// monthly update job). On error the previous database stays in use.
func (g *geoDB) reloadIfChanged() (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st, err := os.Stat(g.path)
	if err != nil {
		return false, err
	}
	if g.r.Load() != nil && st.ModTime().Equal(g.mtime) && st.Size() == g.size {
		return false, nil
	}
	b, err := os.ReadFile(g.path)
	if err != nil {
		return false, err
	}
	r, err := maxminddb.FromBytes(b)
	if err != nil {
		return false, fmt.Errorf("geoip_db %s: %w", g.path, err)
	}
	g.r.Store(r)
	g.mtime, g.size = st.ModTime(), st.Size()
	return true, nil
}

// lookup returns the ISO country and continent codes of ip ("" when unknown).
func (g *geoDB) lookup(ip net.IP) (country, continent string) {
	if g == nil || ip == nil {
		return "", ""
	}
	r := g.r.Load()
	if r == nil {
		return "", ""
	}
	var rec geoRecord
	if err := r.Lookup(ip, &rec); err != nil {
		return "", ""
	}
	country = rec.Country.ISOCode
	if country == "" {
		country = rec.Registered.ISOCode
	}
	return strings.ToUpper(country), strings.ToUpper(rec.Continent.Code)
}
