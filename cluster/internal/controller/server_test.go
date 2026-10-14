package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
)

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	cfg := &config.Controller{
		StateFile:        filepath.Join(t.TempDir(), "state.json"),
		AdminToken:       "admin",
		NodeToken:        "node",
		DNSToken:         "dns",
		HeartbeatTimeout: config.Duration{Duration: time.Minute},
		ProbeTimeout:     config.Duration{Duration: time.Second},
		Brand:            config.Brand{Name: "HiTechCloud WAF", PrimaryColor: "#1D4ED8"},
	}
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func do(t *testing.T, ts *httptest.Server, method, path, token string, body any) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, ts.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func hb(id, ip, region string, pools ...string) api.Heartbeat {
	return api.Heartbeat{ID: id, IPv4: ip, Region: region, Pools: pools, EngineHealthy: true, Weight: 100}
}

func TestHeartbeatAuthAndEndpoints(t *testing.T) {
	_, ts := newTestServer(t)

	if r := do(t, ts, "POST", "/v1/heartbeat", "admin", hb("n1", "203.0.113.1", "hn")); r.StatusCode != 401 {
		t.Fatalf("admin token must not register nodes, got %d", r.StatusCode)
	}
	for _, h := range []api.Heartbeat{hb("n1", "203.0.113.1", "hn", "web"), hb("n2", "203.0.113.2", "hcm", "web")} {
		if r := do(t, ts, "POST", "/v1/heartbeat", "node", h); r.StatusCode != 200 {
			t.Fatalf("heartbeat: %d", r.StatusCode)
		}
	}
	bad := hb("n3", "203.0.113.3", "hn")
	bad.EngineHealthy, bad.EngineError = false, "detector down"
	do(t, ts, "POST", "/v1/heartbeat", "node", bad)

	if r := do(t, ts, "GET", "/v1/pools/web/endpoints", "node", nil); r.StatusCode != 401 {
		t.Fatalf("node token must not read pools: %d", r.StatusCode)
	}
	r := do(t, ts, "GET", "/v1/pools/web/endpoints", "dns", nil)
	var pe api.PoolEndpoints
	_ = json.NewDecoder(r.Body).Decode(&pe)
	if len(pe.Endpoints) != 2 || !pe.Endpoints[0].Healthy || !pe.Endpoints[1].Healthy {
		t.Fatalf("endpoints = %+v", pe)
	}

	r = do(t, ts, "GET", "/v1/pools/default/endpoints", "dns", nil)
	pe = api.PoolEndpoints{}
	_ = json.NewDecoder(r.Body).Decode(&pe)
	if len(pe.Endpoints) != 1 || pe.Endpoints[0].Healthy {
		t.Fatalf("unhealthy engine must be reported unhealthy: %+v", pe)
	}

	// Drain removes the node from DNS.
	drain := true
	if r := do(t, ts, "PATCH", "/v1/nodes/n1", "admin", api.NodePatch{Drain: &drain}); r.StatusCode != 200 {
		t.Fatalf("patch: %d", r.StatusCode)
	}
	r = do(t, ts, "GET", "/v1/pools/web/endpoints", "dns", nil)
	pe = api.PoolEndpoints{}
	_ = json.NewDecoder(r.Body).Decode(&pe)
	if len(pe.Endpoints) != 1 || pe.Endpoints[0].NodeID != "n2" {
		t.Fatalf("drained node still served: %+v", pe)
	}
}

func TestProbeURLMustTargetNode(t *testing.T) {
	_, ts := newTestServer(t)
	h := hb("n1", "203.0.113.1", "hn")
	h.ProbeURL = "http://169.254.169.254/latest/meta-data"
	if r := do(t, ts, "POST", "/v1/heartbeat", "node", h); r.StatusCode != 400 {
		t.Fatalf("probe to foreign host accepted: %d", r.StatusCode)
	}
	h.ProbeURL = "http://203.0.113.1:80/"
	if r := do(t, ts, "POST", "/v1/heartbeat", "node", h); r.StatusCode != 200 {
		t.Fatalf("valid probe rejected: %d", r.StatusCode)
	}
	h.ID = "../etc"
	if r := do(t, ts, "POST", "/v1/heartbeat", "node", h); r.StatusCode != 400 {
		t.Fatalf("bad id accepted: %d", r.StatusCode)
	}
}

func TestProbeAndHeartbeatTimeout(t *testing.T) {
	s, _ := newTestServer(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403) }))
	defer up.Close()
	u, _ := url.Parse(up.URL)

	h := hb("n1", "127.0.0.1", "hn")
	h.ProbeURL = "http://" + u.Host + "/"
	if _, err := s.Store().Heartbeat(h); err != nil {
		t.Fatal(err)
	}
	s.ProbeAll(context.Background())
	n, _ := s.Store().Get("n1")
	if !n.Healthy {
		t.Fatalf("403 from WAF should count as up: %+v", n)
	}

	up.Close()
	s.ProbeAll(context.Background())
	n, _ = s.Store().Get("n1")
	if n.Healthy || n.ProbeOK {
		t.Fatalf("closed port should be unhealthy: %+v", n)
	}

	// Heartbeat timeout.
	s.store.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	s.Store().Evaluate(time.Minute, 0)
	n, _ = s.Store().Get("n1")
	if n.Healthy || n.Reason != "heartbeat timeout" {
		t.Fatalf("expected heartbeat timeout: %+v", n)
	}
}

func TestStatePersistsAdminChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	st, _ := NewStore(path)
	if _, err := st.Heartbeat(hb("n1", "203.0.113.1", "hn")); err != nil {
		t.Fatal(err)
	}
	w := 7
	if _, err := st.Patch("n1", api.NodePatch{WeightOverride: &w}); err != nil {
		t.Fatal(err)
	}
	st2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	n, ok := st2.Get("n1")
	if !ok || n.WeightOverride != 7 || n.Healthy {
		t.Fatalf("restored node = %+v", n)
	}
}

func TestDashboardIsBranded(t *testing.T) {
	_, ts := newTestServer(t)
	r := do(t, ts, "GET", "/", "", nil)
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || !bytes.Contains(b, []byte("HiTechCloud WAF · Cluster")) {
		t.Fatalf("dashboard: %d", r.StatusCode)
	}
}
