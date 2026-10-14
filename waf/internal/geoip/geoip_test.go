package geoip

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// WriteTestDB writes a tiny country database mapping CIDRs to ISO codes.
func WriteTestDB(t *testing.T, entries map[string]string) string {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "Test-Country", RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	for cidr, code := range entries {
		_, n, _ := net.ParseCIDR(cidr)
		if err := w.Insert(n, mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(code)}}); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(t.TempDir(), "country.mmdb")
	f, _ := os.Create(p)
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCountryLookupAndReload(t *testing.T) {
	db, err := Open(WriteTestDB(t, map[string]string{"203.0.113.0/24": "VN", "198.51.100.0/24": "US"}))
	if err != nil {
		t.Fatal(err)
	}
	if c := db.Country(net.ParseIP("203.0.113.9")); c != "VN" {
		t.Fatalf("got %q", c)
	}
	if c := db.Country(net.ParseIP("192.0.2.1")); c != "" {
		t.Fatalf("unknown got %q", c)
	}
	if err := db.Reload(WriteTestDB(t, map[string]string{"203.0.113.0/24": "SG"})); err != nil {
		t.Fatal(err)
	}
	if c := db.Country(net.ParseIP("203.0.113.9")); c != "SG" {
		t.Fatalf("after reload got %q", c)
	}
	var nilDB *DB
	if nilDB.Country(net.ParseIP("1.1.1.1")) != "" {
		t.Fatal("nil db")
	}
}
