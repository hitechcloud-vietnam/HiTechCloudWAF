package mgmt

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/store"
)

const token = "0123456789abcdef0123"

func setup(t *testing.T) (*httptest.Server, *[]model.Site, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := events.New(10, "")
	applied := &[]model.Site{}
	api := &API{Token: token, Store: st, Events: ev, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Apply: func(s []model.Site, _ []model.Cert) error { *applied = s; return nil }}
	ts := httptest.NewServer(api.Handler())
	t.Cleanup(ts.Close)
	return ts, applied, st
}

func call(t *testing.T, ts *httptest.Server, method, path string, body any, tok string) (int, envelope) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, ts.URL+path, rd)
	if tok != "" {
		req.Header.Set(TokenHeader, tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var env envelope
	_ = json.NewDecoder(resp.Body).Decode(&env)
	return resp.StatusCode, env
}

func TestAuth(t *testing.T) {
	ts, _, _ := setup(t)
	if code, _ := call(t, ts, "GET", "/api/open/health", nil, ""); code != 200 {
		t.Fatal("health must be public")
	}
	if code, _ := call(t, ts, "GET", "/api/open/site", nil, ""); code != 401 {
		t.Fatal("site list without token")
	}
	if code, _ := call(t, ts, "GET", "/api/open/site", nil, "wrong-token-wrong-token"); code != 401 {
		t.Fatal("site list with wrong token")
	}
}

func TestSiteCRUDAppliesAndPersists(t *testing.T) {
	ts, applied, _ := setup(t)
	site := model.Site{ServerNames: []string{"Shop.Example.VN"}, Upstreams: []string{"http://10.0.0.1:8080"}}
	if code, env := call(t, ts, "POST", "/api/open/site", site, token); code != 200 || env.Err != nil {
		t.Fatalf("create: %d %+v", code, env)
	}
	if len(*applied) != 1 || (*applied)[0].ServerNames[0] != "shop.example.vn" || (*applied)[0].Mode != model.ModeBlock {
		t.Fatalf("applied = %+v", *applied)
	}
	// Same name on the same port is a conflict.
	if code, _ := call(t, ts, "POST", "/api/open/site", site, token); code != 400 {
		t.Fatalf("duplicate accepted: %d", code)
	}
	// Invalid input.
	bad := model.Site{ServerNames: []string{"x.vn"}, Upstreams: []string{"ftp://nope"}}
	if code, env := call(t, ts, "POST", "/api/open/site", bad, token); code != 400 || env.Err == nil {
		t.Fatalf("bad upstream accepted: %d", code)
	}
	ssl := model.Site{ServerNames: []string{"y.vn"}, Ports: []string{"443_ssl"}, Upstreams: []string{"http://10.0.0.2"}}
	if code, _ := call(t, ts, "POST", "/api/open/site", ssl, token); code != 400 {
		t.Fatalf("ssl port without cert accepted: %d", code)
	}

	id := (*applied)[0].ID
	upd := (*applied)[0]
	upd.Mode = model.ModeMonitor
	if code, _ := call(t, ts, "PUT", "/api/open/site", upd, token); code != 200 || (*applied)[0].Mode != model.ModeMonitor {
		t.Fatalf("update failed: %d", code)
	}
	_, env := call(t, ts, "GET", "/api/open/site", nil, token)
	data := env.Data.(map[string]any)
	if data["total"].(float64) != 1 {
		t.Fatalf("list = %+v", data)
	}
	if code, _ := call(t, ts, "DELETE", "/api/open/site", map[string]any{"ids": []int{id}}, token); code != 200 || len(*applied) != 0 {
		t.Fatalf("delete failed: %d", code)
	}
	if code, _ := call(t, ts, "DELETE", "/api/open/site", map[string]any{"ids": []int{id}}, token); code != 404 {
		t.Fatalf("delete unknown: %d", code)
	}
}

func TestStoreReload(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	st, _ := store.Open(p)
	if _, err := st.CreateSite(model.Site{ServerNames: []string{"a.vn"}, Upstreams: []string{"http://1.1.1.1"}}); err != nil {
		t.Fatal(err)
	}
	st2, err := store.Open(p)
	if err != nil || len(st2.Sites()) != 1 {
		t.Fatalf("reload: %v %d", err, len(st2.Sites()))
	}
	// IDs keep increasing after reload.
	s, _ := st2.CreateSite(model.Site{ServerNames: []string{"b.vn"}, Upstreams: []string{"http://1.1.1.1"}})
	if s.ID != 2 {
		t.Fatalf("id = %d", s.ID)
	}
}

func TestConsoleAndBrandArePublicAPIIsNot(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "c.json"))
	ev, _ := events.New(10, "")
	api := &API{Token: token, Store: st, Events: ev, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Brand: map[string]string{"name": "Acme WAF"}, Console: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "console") }),
		Apply: func([]model.Site, []model.Cert) error { return nil }}
	ts := httptest.NewServer(api.Handler())
	defer ts.Close()
	for path, want := range map[string]int{"/": 200, "/sites/1": 200, "/api/open/brand": 200, "/api/open/info": 401, "/api/open/timeseries": 401, "/api/open/unknown": 401} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: %d, want %d", path, resp.StatusCode, want)
		}
	}
	if code, env := call(t, ts, "GET", "/api/open/timeseries", nil, token); code != 200 || len(env.Data.([]any)) != 60 {
		t.Fatalf("timeseries: %d", code)
	}
}

func TestAllowList(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "c.json"))
	ev, _ := events.New(10, "")
	only, _ := model.ParseCIDR("10.0.0.0/8")
	api := &API{Token: token, Store: st, Events: ev, Allow: []*net.IPNet{only}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ts := httptest.NewServer(api.Handler())
	defer ts.Close()
	if code, _ := call(t, ts, "GET", "/api/open/site", nil, token); code != 403 {
		t.Fatalf("loopback client not in allow list got %d", code)
	}
}

func TestMetrics(t *testing.T) {
	ts, _, st := setup(t)
	if _, err := st.CreateSite(model.Site{ServerNames: []string{"m.vn"}, Upstreams: []string{"http://1.1.1.1"}}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/open/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(b, []byte("# TYPE hcw_requests_total counter")) || !bytes.Contains(b, []byte("hcw_sites 1")) {
		t.Fatalf("metrics: %d\n%s", resp.StatusCode, b)
	}
}

func TestAlertsTestEndpointWithoutChannels(t *testing.T) {
	ts, _, _ := setup(t)
	if code, env := call(t, ts, "POST", "/api/open/alerts/test", nil, token); code != 409 || env.Err == nil {
		t.Fatalf("got %d", code)
	}
}
