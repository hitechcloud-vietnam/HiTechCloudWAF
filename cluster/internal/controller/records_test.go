package controller

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
)

func TestDNSRecordsCRUD(t *testing.T) {
	s, ts := newTestServer(t)
	rec := api.DNSRecord{Zone: "Example.VN.", Name: "WWW", Type: "a", Value: "192.0.2.1", Comment: "web"}

	if r := do(t, ts, "POST", "/v1/dns/records", "dns", rec); r.StatusCode != 401 {
		t.Fatalf("dns token must not write records: %d", r.StatusCode)
	}
	if r := do(t, ts, "GET", "/v1/dns/records", "node", nil); r.StatusCode != 401 {
		t.Fatalf("node token must not read records: %d", r.StatusCode)
	}
	r := do(t, ts, "POST", "/v1/dns/records", "admin", rec)
	if r.StatusCode != 201 {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("create: %d %s", r.StatusCode, b)
	}
	var created api.DNSRecord
	_ = json.NewDecoder(r.Body).Decode(&created)
	if created.ID == "" || created.Zone != "example.vn" || created.Name != "www" || created.Type != "A" {
		t.Fatalf("created = %+v", created)
	}

	for _, c := range []struct {
		rec  api.DNSRecord
		code int
	}{
		{api.DNSRecord{Zone: "example.vn", Name: "www", Type: "A", Value: "192.0.2.1"}, 409},             // duplicate
		{api.DNSRecord{Zone: "example.vn", Name: "www", Type: "CNAME", Value: "edge"}, 409},              // CNAME next to data
		{api.DNSRecord{Zone: "example.vn", Name: "www", Type: "A", Value: "nope"}, 400},                  // invalid value
		{api.DNSRecord{Zone: "example.vn", Name: "@", Type: "CNAME", Value: "edge"}, 400},                // apex CNAME
		{api.DNSRecord{Zone: "", Name: "x", Type: "A", Value: "192.0.2.1"}, 400},                         // no zone
		{api.DNSRecord{Zone: "example.vn", Name: "x", Type: "A", Value: "192.0.2.1", TTL: 1 << 30}, 400}, // ttl
		{api.DNSRecord{Zone: "example.vn", Name: "www", Type: "A", Value: "192.0.2.2"}, 201},             // second address
		{api.DNSRecord{Zone: "example.vn", Name: "*.app", Type: "TXT", Value: "hello world"}, 201},       // wildcard
	} {
		if r := do(t, ts, "POST", "/v1/dns/records", "admin", c.rec); r.StatusCode != c.code {
			b, _ := io.ReadAll(r.Body)
			t.Errorf("%+v: got %d want %d (%s)", c.rec, r.StatusCode, c.code, b)
		}
	}

	r = do(t, ts, "GET", "/v1/dns/records", "dns", nil)
	var set api.DNSRecordSet
	_ = json.NewDecoder(r.Body).Decode(&set)
	etag := r.Header.Get("ETag")
	if len(set.Records) != 3 || set.Serial == 0 || etag == "" {
		t.Fatalf("set = %+v etag=%q", set, etag)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/v1/dns/records", nil)
	req.Header.Set("Authorization", "Bearer dns")
	req.Header.Set("If-None-Match", etag)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 304 {
		t.Fatalf("If-None-Match: %d", resp.StatusCode)
	}

	// Update: a record may keep its own owner without conflicting with itself.
	created.Value, created.TTL = "192.0.2.9", 120
	if r := do(t, ts, "PUT", "/v1/dns/records/"+created.ID, "admin", created); r.StatusCode != 200 {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("update: %d %s", r.StatusCode, b)
	}
	if r := do(t, ts, "PUT", "/v1/dns/records/missing", "admin", created); r.StatusCode != 404 {
		t.Fatalf("update missing: %d", r.StatusCode)
	}
	got, ok := s.Records().Get(created.ID)
	if !ok || got.Value != "192.0.2.9" || got.TTL != 120 {
		t.Fatalf("updated = %+v", got)
	}
	if after := s.Records().Set("").Serial; after <= set.Serial {
		t.Fatalf("serial did not move: %d -> %d", set.Serial, after)
	}

	if r := do(t, ts, "DELETE", "/v1/dns/records/"+created.ID, "admin", nil); r.StatusCode != 204 {
		t.Fatalf("delete: %d", r.StatusCode)
	}
	if r := do(t, ts, "GET", "/v1/dns/records/"+created.ID, "admin", nil); r.StatusCode != 404 {
		t.Fatalf("deleted record still there: %d", r.StatusCode)
	}
	if n := len(s.Records().Set("EXAMPLE.vn.").Records); n != 2 {
		t.Fatalf("zone filter: %d", n)
	}
}

func TestDNSRecordsPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-records.json")
	st, _ := NewRecordStore(path)
	rec, err := st.Create(api.DNSRecord{Zone: "example.vn", Name: "@", Type: "MX", Value: "10 mail"})
	if err != nil {
		t.Fatal(err)
	}
	st2, err := NewRecordStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := st2.Get(rec.ID)
	if !ok || got.Value != "10 mail" || st2.Set("").Serial != st.Set("").Serial {
		t.Fatalf("restored = %+v", got)
	}
	// Changes within the same second still move the serial forward.
	st2.now = func() time.Time { return time.Unix(1, 0) }
	before := st2.Set("").Serial
	if err := st2.Delete(rec.ID); err != nil {
		t.Fatal(err)
	}
	if st2.Set("").Serial != before+1 {
		t.Fatal("serial must be monotonic")
	}
}

func TestDNSRecordsFileNextToState(t *testing.T) {
	s, _ := newTestServer(t)
	if _, err := s.Records().Create(api.DNSRecord{Zone: "example.vn", Name: "www", Type: "A", Value: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	st, err := NewRecordStore(filepath.Join(filepath.Dir(s.cfg.StateFile), "dns-records.json"))
	if err != nil || len(st.Set("").Records) != 1 {
		t.Fatal("records not persisted next to state_file")
	}
}

func TestDashboardHasDNSRecords(t *testing.T) {
	_, ts := newTestServer(t)
	r := do(t, ts, "GET", "/", "", nil)
	b, _ := io.ReadAll(r.Body)
	if !bytes.Contains(b, []byte(`id="records"`)) || !bytes.Contains(b, []byte("/v1/dns/records")) {
		t.Fatal("dashboard has no DNS record section")
	}
	for _, banned := range []string{"chaitin", "safeline", "slce"} {
		if bytes.Contains(bytes.ToLower(b), []byte(banned)) {
			t.Fatalf("dashboard mentions %q", banned)
		}
	}
}
