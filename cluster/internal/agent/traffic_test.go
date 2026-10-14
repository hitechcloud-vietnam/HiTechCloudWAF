package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/controller"
)

type statsEngine struct {
	mu     sync.Mutex
	events []map[string]any // newest first
}

func (e *statsEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var data any = "ok"
	switch r.URL.Path {
	case "/api/open/stats":
		data = map[string]any{"1": map[string]any{"requests": 10, "blocked": 2}, "2": map[string]any{"requests": 5, "rate_limited": 1}}
	case "/api/open/events":
		data = map[string]any{"data": e.events}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "err": nil})
}

func (e *statsEngine) push(id, uri string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ev := map[string]any{"id": id, "time": time.Now(), "host": "a.vn", "client_ip": "203.0.113.9", "country": "VN", "method": "GET", "uri": uri, "kind": "waf", "action": "block", "status": 403, "tags": []string{"attack-sqli"}}
	e.events = append([]map[string]any{ev}, e.events...)
}

func TestAgentForwardsTrafficAndEvents(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := &statsEngine{}
	eng.push("e1", "/?id=1")
	es := httptest.NewServer(eng)
	defer es.Close()

	state := filepath.Join(t.TempDir(), "s.json")
	ctl, err := controller.New(&config.Controller{StateFile: state, AdminToken: "a", NodeToken: "n",
		HeartbeatTimeout: config.Duration{Duration: time.Minute}, ProbeTimeout: config.Duration{Duration: time.Second}}, logger)
	if err != nil {
		t.Fatal(err)
	}
	cs := httptest.NewServer(ctl.Handler())
	defer cs.Close()

	a, err := New(&config.Agent{ControllerURL: cs.URL, NodeToken: "n", ID: "n1", IPv4: "203.0.113.10", DataDir: t.TempDir(),
		Engine: config.Engine{BaseURL: es.URL, TokenHeader: "X", HealthPath: "/api/open/health", Timeout: config.Duration{Duration: 5 * time.Second}}}, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := a.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	eng.push("e2", "/?id=2")
	eng.push("e3", "/?id=3")
	if err := a.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Tick(ctx); err != nil { // nothing new
		t.Fatal(err)
	}

	n, _ := ctl.Store().Get("n1")
	if n.Traffic == nil || n.Traffic.Requests != 15 || n.Traffic.Blocked != 2 || n.Traffic.RateLimited != 1 {
		t.Fatalf("traffic = %+v", n.Traffic)
	}
	req, _ := http.NewRequest("GET", cs.URL+"/v1/events", nil)
	req.Header.Set("Authorization", "Bearer a")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var evs []api.Event
	_ = json.NewDecoder(resp.Body).Decode(&evs)
	resp.Body.Close()
	if len(evs) != 3 || evs[0].ID != "e3" || evs[2].ID != "e1" || evs[0].Node != "n1" || evs[0].Country != "VN" {
		t.Fatalf("events = %+v", evs)
	}
	b, _ := os.ReadFile(state)
	if strings.Contains(string(b), "attack-sqli") {
		t.Fatal("events must not be persisted in the node state")
	}
}
