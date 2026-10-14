package mgmt

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/audit"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/store"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/users"
)

type eventsFixture struct {
	ts      *httptest.Server
	st      *store.Store
	audit   *audit.Log
	applied *int
	admin   string // session tokens
	viewer  string
}

func setupEvents(t *testing.T) *eventsFixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "c.json"))
	if err != nil {
		t.Fatal(err)
	}
	us, _ := users.Open(filepath.Join(dir, "u.json"))
	au, _ := audit.New(filepath.Join(dir, "audit.log"), 100)
	t.Cleanup(func() { au.Close() })
	ev, _ := events.New(100, "")
	now := time.Now().UTC()
	for _, e := range []events.Event{
		{ID: "old", Time: now.Add(-48 * time.Hour), SiteID: 1, ClientIP: "198.51.100.9", Kind: "waf", Action: "block", URI: "/old", Rules: []events.Rule{{ID: 942100, Msg: "SQL Injection"}}},
		{ID: "sqli", Time: now.Add(-30 * time.Minute), SiteID: 1, Host: "shop.vn", ClientIP: "203.0.113.7", Country: "VN", Kind: "waf", Action: "block", Method: "GET",
			URI: "/login?id=1'+OR+1=1", UA: "sqlmap/1.7", Status: 403, Rules: []events.Rule{{ID: 942100, Msg: "SQL Injection"}, {ID: 949110, Msg: "Inbound Anomaly Score Exceeded"}}, Tags: []string{"attack-sqli"}},
		{ID: "xss", Time: now.Add(-5 * time.Minute), SiteID: 1, Host: "shop.vn", ClientIP: "203.0.113.8", Country: "VN", Kind: "waf", Action: "monitor", Method: "GET",
			URI: "/search?q=<script>", UA: "=HYPERLINK(\"http://evil\")", Status: 200, Rules: []events.Rule{{ID: 941100, Msg: "XSS, \"quoted\"\nline"}}},
		{ID: "rate", Time: now.Add(-time.Minute), SiteID: 2, Host: "api.vn", ClientIP: "2001:db8::5", Kind: "rate_limit", Action: "block", Method: "POST",
			URI: "/api", UA: "@evil", Status: 429},
	} {
		ev.Add(e)
	}
	applied := 0
	api := &API{Token: token, Store: st, Users: us, Events: ev, Audit: au, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Apply: func([]model.Site, []model.Cert) error { applied++; return nil }}
	ts := httptest.NewServer(api.Handler())
	t.Cleanup(ts.Close)
	for _, s := range []model.Site{
		{ServerNames: []string{"shop.vn"}, Upstreams: []string{"http://10.0.0.1"}, IPDeny: []string{"203.0.113.7"}},
		{ServerNames: []string{"api.vn"}, Upstreams: []string{"http://10.0.0.2"}},
	} {
		if _, err := st.CreateSite(s); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range [][2]string{{"admin", "admin"}, {"xem", "viewer"}} {
		if err := us.Create(u[0], "Mat-khau-dai-2026", u[1]); err != nil {
			t.Fatal(err)
		}
	}
	f := &eventsFixture{ts: ts, st: st, audit: au, applied: &applied}
	_, f.admin, _ = login(t, ts, "admin", "Mat-khau-dai-2026", "")
	_, f.viewer, _ = login(t, ts, "xem", "Mat-khau-dai-2026", "")
	return f
}

// get performs a GET as a session and returns the status and raw body.
func (f *eventsFixture) get(t *testing.T, path, session string) (int, http.Header, []byte) {
	t.Helper()
	r, _ := http.NewRequest("GET", f.ts.URL+path, nil)
	if session != "" {
		r.Header.Set(SessionHeader, session)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

func (f *eventsFixture) listIDs(t *testing.T, query string) []string {
	t.Helper()
	code, _, b := f.get(t, "/api/open/events?"+query, f.viewer)
	if code != 200 {
		t.Fatalf("%s: %d %s", query, code, b)
	}
	var env struct {
		Data struct {
			Data  []events.Event `json:"data"`
			Total int            `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, e := range env.Data.Data {
		out = append(out, e.ID)
	}
	if env.Data.Total != len(out) {
		t.Errorf("total %d != %d", env.Data.Total, len(out))
	}
	return out
}

func TestEventsListFilters(t *testing.T) {
	f := setupEvents(t)
	since := url.QueryEscape(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	until := url.QueryEscape(time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339))
	for q, want := range map[string][]string{
		"":                                   {"rate", "xss", "sqli", "old"},
		"limit=2":                            {"rate", "xss"},
		"limit=0":                            {"rate", "xss", "sqli", "old"}, // out of range = 100, as before
		"site_id=0":                          {"rate", "xss", "sqli", "old"},
		"site_id=2":                          {"rate"},
		"kind=waf":                           {"xss", "sqli", "old"},
		"kind=waf,rate_limit&site_id=2":      {"rate"},
		"action=monitor":                     {"xss"},
		"ip=203.0.113.7":                     {"sqli"},
		"ip=203.0.113.0/24":                  {"xss", "sqli"},
		"ip=2001:db8::/32":                   {"rate"},
		"country=vn":                         {"xss", "sqli"},
		"rule=942100":                        {"sqli", "old"},
		"rule=942100&since=24h":              {"sqli"},
		"q=SQLMAP":                           {"sqli"},
		"q=api.vn":                           {"rate"},
		"q=%3Cscript":                        {"xss"},
		"since=1h":                           {"rate", "xss", "sqli"},
		"since=" + since + "&until=" + until: {"xss", "sqli"},
	} {
		if got := f.listIDs(t, q); !slices.Equal(got, want) {
			t.Errorf("%q: got %v, want %v", q, got, want)
		}
	}
	for _, bad := range []string{"ip=nope", "since=yesterday", "until=1x", "site_id=x", "rule=abc", "rule=-1", "since=1h&until=2h", "q=" + strings.Repeat("a", 300)} {
		if code, _, _ := f.get(t, "/api/open/events?"+bad, f.viewer); code != 400 {
			t.Errorf("%q: %d, want 400", bad, code)
		}
	}
}

func TestEventsTop(t *testing.T) {
	f := setupEvents(t)
	top := func(q string) (int, map[string]any) {
		code, _, b := f.get(t, "/api/open/events/top?"+q, f.viewer)
		var env struct{ Data map[string]any }
		_ = json.Unmarshal(b, &env)
		return code, env.Data
	}
	code, d := top("by=rule&since=24h")
	if code != 200 || d["total"].(float64) != 3 {
		t.Fatalf("top rule: %d %v", code, d)
	}
	items := d["items"].([]any)
	first := items[0].(map[string]any)
	if first["key"] != "942100" && first["key"] != "941100" && first["key"] != "949110" {
		t.Fatalf("items: %v", items)
	}
	if len(items) != 3 {
		t.Errorf("rule items: %v", items)
	}
	code, d = top("by=ip")
	if code != 200 || len(d["items"].([]any)) != 4 || d["by"] != "ip" {
		t.Errorf("top ip: %d %v", code, d)
	}
	code, d = top("by=uri&kind=waf&since=1h")
	if code != 200 {
		t.Fatal(code)
	}
	var keys []string
	for _, it := range d["items"].([]any) {
		keys = append(keys, it.(map[string]any)["key"].(string))
	}
	if !slices.Equal(keys, []string{"/login", "/search"}) {
		t.Errorf("top uri: %v", keys)
	}
	code, d = top("by=country")
	if code != 200 || len(d["items"].([]any)) != 1 {
		t.Errorf("top country: %v", d)
	}
	if code, _ := top("by=method"); code != 400 {
		t.Errorf("unknown by: %d", code)
	}
	if code, d := top(""); code != 200 || d["by"] != "ip" {
		t.Errorf("default by: %d %v", code, d)
	}
}

func TestEventsExportCSV(t *testing.T) {
	f := setupEvents(t)
	code, h, b := f.get(t, "/api/open/events/export?format=csv&site_id=1", f.viewer)
	if code != 200 {
		t.Fatalf("export: %d %s", code, b)
	}
	if ct := h.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content type %q", ct)
	}
	if cd := h.Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.HasSuffix(cd, `.csv"`) {
		t.Errorf("disposition %q", cd)
	}
	rows, err := csv.NewReader(strings.NewReader(string(b))).ReadAll()
	if err != nil {
		t.Fatalf("CSV does not parse: %v\n%s", err, b)
	}
	if !slices.Equal(rows[0], csvColumns) || len(rows) != 4 {
		t.Fatalf("rows: %v", rows)
	}
	col := func(row []string, name string) string { return row[slices.Index(csvColumns, name)] }
	xss := rows[1]
	if col(xss, "id") != "xss" || col(xss, "site") != "shop.vn" {
		t.Fatalf("first row: %v", xss)
	}
	if got := col(xss, "user_agent"); got != `'=HYPERLINK("http://evil")` {
		t.Errorf("formula not neutralised: %q", got)
	}
	if got := col(xss, "rule_msgs"); got != "XSS, \"quoted\"\nline" {
		t.Errorf("quoting round trip: %q", got)
	}
	if got := col(rows[2], "rule_ids"); got != "942100 949110" {
		t.Errorf("rule ids: %q", got)
	}
	// The second site's "@evil" agent.
	_, _, b = f.get(t, "/api/open/events/export?site_id=2", f.viewer)
	rows, _ = csv.NewReader(strings.NewReader(string(b))).ReadAll()
	if len(rows) != 2 || col(rows[1], "user_agent") != "'@evil" {
		t.Errorf("default csv / @ prefix: %v", rows)
	}
	// Exports are audited.
	found := false
	for _, e := range f.audit.Latest(10) {
		if e.Action == "GET /api/open/events/export" && e.User == "xem" {
			found = true
		}
	}
	if !found {
		t.Error("export not audited")
	}
}

func TestCSVCell(t *testing.T) {
	for in, want := range map[string]string{
		"=1+1": "'=1+1", "+1": "'+1", "-2": "'-2", "@SUM(A1)": "'@SUM(A1)", "\tx": "'\tx", "\rx": "'\rx",
		"": "", "/login": "/login", "a=b": "a=b", "1-2": "1-2",
	} {
		if got := csvCell(in); got != want {
			t.Errorf("csvCell(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEventsExportJSON(t *testing.T) {
	f := setupEvents(t)
	code, h, b := f.get(t, "/api/open/events/export?format=json&kind=waf&since=24h", f.admin)
	if code != 200 || !strings.HasPrefix(h.Get("Content-Type"), "application/json") {
		t.Fatalf("export: %d %s", code, h)
	}
	var ev []events.Event
	if err := json.Unmarshal(b, &ev); err != nil {
		t.Fatal(err)
	}
	if len(ev) != 2 || ev[0].ID != "xss" || ev[1].ID != "sqli" {
		t.Errorf("json export: %+v", ev)
	}
	if code, _, _ := f.get(t, "/api/open/events/export?format=xml", f.admin); code != 400 {
		t.Errorf("bad format: %d", code)
	}
	if code, _, _ := f.get(t, "/api/open/events/export", ""); code != 401 {
		t.Errorf("anonymous export: %d", code)
	}
}

func TestDenyIPRoute(t *testing.T) {
	f := setupEvents(t)
	// Viewers may read, but not change the configuration.
	for _, p := range []string{"/api/open/events", "/api/open/events/top?by=ip", "/api/open/events/export?format=csv"} {
		if code, _, _ := f.get(t, p, f.viewer); code != 200 {
			t.Errorf("viewer %s: %d", p, code)
		}
	}
	body := map[string]any{"ip": "203.0.113.7"}
	if code, _ := req(t, f.ts, "POST", "/api/open/site/ip-deny", f.viewer, body); code != 403 {
		t.Fatalf("viewer deny: %d", code)
	}
	if *f.applied != 0 {
		t.Fatal("viewer request applied")
	}
	code, env := req(t, f.ts, "POST", "/api/open/site/ip-deny", f.admin, body)
	if code != 200 {
		t.Fatalf("admin deny: %d %+v", code, env)
	}
	d := env.Data.(map[string]any)
	if d["ip"] != "203.0.113.7/32" || len(d["added"].([]any)) != 1 || len(d["unchanged"].([]any)) != 1 {
		t.Errorf("result: %v", d)
	}
	if *f.applied != 1 {
		t.Errorf("applied %d times, want once", *f.applied)
	}
	for _, s := range f.st.Sites() {
		if n := slices.Index(s.IPDeny, "203.0.113.7/32"); n < 0 || len(s.IPDeny) != 1 {
			t.Errorf("site %d deny list: %v", s.ID, s.IPDeny)
		}
	}
	// One site, a prefix.
	code, env = req(t, f.ts, "POST", "/api/open/site/ip-deny", f.admin, map[string]any{"ip": "198.51.100.0/24", "site_ids": []int{2}})
	if code != 200 {
		t.Fatalf("one site: %d %+v", code, env)
	}
	if s := f.st.Sites(); len(s[0].IPDeny) != 1 || len(s[1].IPDeny) != 2 {
		t.Errorf("deny lists: %v / %v", s[0].IPDeny, s[1].IPDeny)
	}
	for _, c := range []struct {
		body map[string]any
		code int
	}{
		{map[string]any{"ip": "not-an-ip"}, 400},
		{map[string]any{"ip": "0.0.0.0/0"}, 400},
		{map[string]any{"ip": "203.0.113.9", "site_ids": []int{99}}, 404},
	} {
		if code, _ := req(t, f.ts, "POST", "/api/open/site/ip-deny", f.admin, c.body); code != c.code {
			t.Errorf("%v: %d, want %d", c.body, code, c.code)
		}
	}
	// The action is audited like every change.
	found := false
	for _, e := range f.audit.Latest(20) {
		if e.Action == "POST /api/open/site/ip-deny" && e.User == "admin" && e.Status == 200 {
			found = true
		}
	}
	if !found {
		t.Error("deny not audited")
	}
}
