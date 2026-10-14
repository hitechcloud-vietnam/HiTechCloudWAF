package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

func TestActiveHealthCheck(t *testing.T) {
	var sick atomic.Bool
	mk := func(name string, check func() bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				if check() {
					w.WriteHeader(500)
					return
				}
				_, _ = io.WriteString(w, "ok")
				return
			}
			_, _ = io.WriteString(w, name)
		}))
	}
	a := mk("A", sick.Load)
	b := mk("B", func() bool { return false })
	defer a.Close()
	defer b.Close()

	h := newHarness(t, nil, model.Site{ServerNames: []string{"hc.vn"}, Mode: model.ModeOff,
		Upstreams: []string{a.URL, b.URL}, Health: model.HealthCheck{Path: "/healthz", Unhealthy: 2, Healthy: 2}})
	s := h.eng.rt.Load().ports[h.port].exact["hc.vn"]
	probe := func(n int) {
		for i := 0; i < n; i++ {
			for _, u := range s.upstreams {
				h.eng.checkUpstream(context.Background(), s, u)
			}
		}
	}
	served := func() string {
		seen := map[string]bool{}
		for i := 0; i < 6; i++ {
			_, body := h.get(t, "hc.vn", "/", nil)
			seen[body] = true
		}
		keys := []string{}
		for k := range seen {
			keys = append(keys, k)
		}
		return strings.Join(keys, "")
	}

	probe(1)
	if got := served(); len(got) != 2 {
		t.Fatalf("both upstreams should serve, got %q", got)
	}
	sick.Store(true)
	probe(1)
	if !strings.Contains(served(), "A") {
		t.Fatal("one failure must not take A out yet")
	}
	probe(1) // second consecutive failure
	if got := served(); got != "B" {
		t.Fatalf("unhealthy A still served: %q", got)
	}
	st := h.eng.UpstreamStatus()[s.site.ID]
	if st[0].Healthy || st[0].LastError != "HTTP 500" || !st[1].Healthy {
		t.Fatalf("status = %+v", st)
	}

	// State survives a configuration reload.
	if err := h.eng.Apply([]model.Site{s.site}, nil); err != nil {
		t.Fatal(err)
	}
	s = h.eng.rt.Load().ports[h.port].exact["hc.vn"]
	if got := served(); got != "B" {
		t.Fatalf("health state lost on reload: %q", got)
	}

	sick.Store(false)
	probe(1)
	if got := served(); got != "B" {
		t.Fatal("one success must not bring A back yet")
	}
	probe(1)
	if got := served(); len(got) != 2 {
		t.Fatalf("A not back after recovering: %q", got)
	}
}

func TestAllUnhealthyStillServes(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"x.vn"}, Mode: model.ModeOff, Health: model.HealthCheck{Path: "/nope", Unhealthy: 1}})
	s := h.eng.rt.Load().ports[h.port].exact["x.vn"]
	h.origin.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nope" {
			w.WriteHeader(503)
			return
		}
		_, _ = io.WriteString(w, "still here")
	})
	h.eng.checkUpstream(context.Background(), s, s.upstreams[0])
	if code, body := h.get(t, "x.vn", "/", nil); code != 200 || body != "still here" {
		t.Fatalf("with every upstream unhealthy the site must still try one: %d %q", code, body)
	}
}
