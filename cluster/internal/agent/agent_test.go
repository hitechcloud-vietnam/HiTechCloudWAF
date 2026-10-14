package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/controller"
)

// miniEngine stores one collection of sites.
type miniEngine struct {
	mu    sync.Mutex
	next  int
	sites []map[string]any
	down  bool
}

func (e *miniEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r.Header.Get("X-SLCE-API-TOKEN") != "t" {
		w.WriteHeader(401)
		return
	}
	if r.URL.Path == "/api/open/health" {
		if e.down {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{"data":"ok","err":null}`))
		return
	}
	switch r.Method {
	case "GET":
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": e.sites}, "err": nil})
	case "POST":
		var it map[string]any
		_ = json.NewDecoder(r.Body).Decode(&it)
		e.next++
		it["id"] = e.next
		e.sites = append(e.sites, it)
		_, _ = w.Write([]byte(`{"data":null,"err":null}`))
	}
}

func TestAgentRegistersAndReplicates(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	primary := &miniEngine{next: 10, sites: []map[string]any{{"id": 1, "server_names": []any{"a.vn"}, "upstreams": []any{"http://10.0.0.1"}}}}
	replica := &miniEngine{next: 100}
	ps, rs := httptest.NewServer(primary), httptest.NewServer(replica)
	defer ps.Close()
	defer rs.Close()

	res := []config.Resource{{Name: "site", Path: "/api/open/site", ItemsPath: "data.data", IDField: "id", KeyFields: []string{"server_names"}, UpdateMethod: "PUT", DeleteMode: "body_ids"}}
	engineCfg := func(u string) config.Engine {
		return config.Engine{BaseURL: u, Token: "t", TokenHeader: "X-SLCE-API-TOKEN", HealthPath: "/api/open/health", Timeout: config.Duration{Duration: 5 * time.Second}, Resources: res}
	}
	ccfg := &config.Controller{
		StateFile: filepath.Join(t.TempDir(), "s.json"), AdminToken: "a", NodeToken: "n", DNSToken: "d",
		HeartbeatTimeout: config.Duration{Duration: time.Minute}, ProbeTimeout: config.Duration{Duration: time.Second},
		Primary: engineCfg(ps.URL),
	}
	ctl, err := controller.New(ccfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctl.RefreshSnapshot(context.Background())
	cs := httptest.NewServer(ctl.Handler())
	defer cs.Close()

	ecfg := engineCfg(rs.URL)
	ecfg.Resources = nil
	a, err := New(&config.Agent{
		ControllerURL: cs.URL, NodeToken: "n", ID: "node-1", IPv4: "203.0.113.10", Region: "hn",
		Pools: []string{"web"}, DataDir: t.TempDir(), Interval: config.Duration{Duration: time.Second},
		Engine: ecfg, ApplyConfig: true,
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(replica.sites) != 1 || replica.sites[0]["id"] != 101 {
		t.Fatalf("replica sites = %v", replica.sites)
	}
	if a.appliedRev == "" || a.configErr != "" {
		t.Fatalf("rev=%q err=%q", a.appliedRev, a.configErr)
	}
	// Second tick reports the revision; nothing re-applied.
	if err := a.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	n, ok := ctl.Store().Get("node-1")
	if !ok || !n.Healthy || n.ConfigRevision != a.appliedRev {
		t.Fatalf("node = %+v", n)
	}

	replica.mu.Lock()
	replica.down = true
	replica.mu.Unlock()
	_ = a.Tick(context.Background())
	n, _ = ctl.Store().Get("node-1")
	if n.Healthy {
		t.Fatal("node with failing engine must be unhealthy")
	}
}
