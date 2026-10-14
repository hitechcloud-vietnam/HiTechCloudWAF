package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func ev(id string, site int, uri string) map[string]any {
	return map[string]any{"id": id, "time": time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC), "site_id": site, "host": "shop.example.com",
		"client_ip": "203.0.113.9", "method": "GET", "uri": uri, "kind": "waf", "action": "block", "status": 403,
		"rules": []map[string]any{{"id": 942100, "msg": "SQLi"}}}
}

func TestEventsList(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/events", map[string]any{"data": []any{ev("e2", 1, "/b"), ev("e1", 1, "/a")}, "total": 2})
	ta := newTestApp(t).loggedIn(f)

	out := ta.mustRun("events", "--site", "1", "--limit", "10")
	r := f.last("GET /api/open/events")
	if r.Query.Get("limit") != "10" || r.Query.Get("site_id") != "1" {
		t.Errorf("query = %v", r.Query)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("output:\n%s", out)
	}
	contains(t, lines[0], "TIME", "CLIENT", "STATUS")
	// Oldest first.
	contains(t, lines[1], "shop.example.com/a", "203.0.113.9", "403", "block", "waf 942100")
	contains(t, lines[2], "/b")

	out = ta.mustRun("events", "-o", "json")
	if f.last("GET /api/open/events").Query.Get("site_id") != "" {
		t.Error("site_id sent without --site")
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil || len(got) != 2 || got[0]["id"] != "e2" {
		t.Errorf("json = %v (%v)", got, err)
	}
	ta.wantExit(2, "events", "--limit", "0")
	ta.wantExit(2, "events", "--limit", "abc")
}

func TestEventsFollow(t *testing.T) {
	for _, format := range []string{"table", "json"} {
		t.Run(format, func(t *testing.T) {
			f := newFake(t)
			var mu sync.Mutex
			newest := 3 // events e1..e3 exist at start
			polls := 0
			f.handle("GET /api/open/events", func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				polls++
				if polls > 1 && newest < 6 {
					newest++ // one new event per poll
				}
				limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
				var data []any
				for i := newest; i >= 1 && len(data) < limit; i-- {
					data = append(data, ev(fmt.Sprintf("e%d", i), 1, fmt.Sprintf("/p%d", i)))
				}
				envelope(w, 200, map[string]any{"data": data, "total": len(data)}, "", "")
			})
			ta := newTestApp(t).loggedIn(f)
			ta.poll = 5 * time.Millisecond

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan int)
			go func() { done <- ta.runCtx(ctx, "events", "--follow", "--limit", "2", "-o", format) }()
			deadline := time.After(10 * time.Second)
			for !strings.Contains(ta.out.String(), "/p6") {
				select {
				case <-deadline:
					cancel()
					t.Fatalf("no /p6 after 10s:\n%s", ta.out.String())
				case <-time.After(5 * time.Millisecond):
				}
			}
			time.Sleep(30 * time.Millisecond) // a few more polls with nothing new
			cancel()
			if code := <-done; code != 0 {
				t.Fatalf("exit %d: %s", code, ta.err.String())
			}
			out := ta.out.String()
			// Initial --limit 2 shows e2,e3; then e4..e6 once each, in order.
			if strings.Contains(out, "/p1") {
				t.Errorf("e1 printed despite --limit 2:\n%s", out)
			}
			order := []string{"/p2", "/p3", "/p4", "/p5", "/p6"}
			for _, p := range order {
				if n := strings.Count(out, p); n != 1 {
					t.Errorf("%s printed %d times:\n%s", p, n, out)
				}
			}
			last := -1
			for _, p := range order {
				i := strings.Index(out, p)
				if i < last {
					t.Errorf("events out of order:\n%s", out)
				}
				last = i
			}
			if format == "json" {
				for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
					var m map[string]any
					if err := json.Unmarshal([]byte(line), &m); err != nil {
						t.Errorf("not NDJSON: %q", line)
					}
				}
			}
			if got := f.last("GET /api/open/events").Query.Get("limit"); got != strconv.Itoa(pollLimit) {
				t.Errorf("poll limit = %s", got)
			}
		})
	}
}

func TestEventsFollowStopsOnAuthError(t *testing.T) {
	f := newFake(t)
	var mu sync.Mutex
	calls := 0
	f.handle("GET /api/open/events", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls > 1 {
			envelope(w, 401, nil, "unauthorized", "session expired")
			return
		}
		envelope(w, 200, map[string]any{"data": []any{}}, "", "")
	})
	ta := newTestApp(t).loggedIn(f)
	ta.poll = 5 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if code := ta.runCtx(ctx, "events", "--follow"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	contains(t, ta.err.String(), "session expired")
}
