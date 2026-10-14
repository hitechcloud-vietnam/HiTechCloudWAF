package alerts

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
)

type sink struct {
	mu   sync.Mutex
	tg   []map[string]any
	hook [][]byte
	sigs []string
}

func (s *sink) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/botTOKEN/sendMessage") {
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			s.tg = append(s.tg, m)
		} else {
			s.hook = append(s.hook, b)
			s.sigs = append(s.sigs, r.Header.Get("X-HCW-Signature"))
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newNotifier(t *testing.T, s *sink) (*Notifier, *time.Time) {
	srv := s.server(t)
	var cfg Config
	cfg.Kinds = []string{"waf", "rate_limit"}
	cfg.Interval = 5 * time.Minute
	cfg.Telegram.BotToken, cfg.Telegram.ChatID, cfg.Telegram.APIBase = "TOKEN", "-100123", srv.URL
	cfg.Webhooks = []Webhook{{URL: srv.URL + "/hook", Secret: "s3cret"}}
	n := New(cfg, "hn-01", func(id int) string { return "shop.vn" }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	n.now = func() time.Time { return now }
	return n, &now
}

func ev(kind, ip, uri string) events.Event {
	return events.Event{ID: "x", Time: time.Now(), SiteID: 1, Host: "shop.vn", ClientIP: ip, Method: "GET", URI: uri, Kind: kind, Action: "block", Tags: []string{"attack-sqli"}}
}

func TestAggregationAndThrottle(t *testing.T) {
	s := &sink{}
	n, now := newNotifier(t, s)
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		n.Observe(ev("waf", "203.0.113.9", "/?id=1'"))
	}
	n.Observe(ev("waf", "198.51.100.1", "/"))
	n.Observe(ev("bot", "1.1.1.1", "/")) // kind not enabled
	n.Observe(events.Event{SiteID: 1, Kind: "waf", Action: "monitor"})
	n.Flush(ctx)
	if len(s.tg) != 1 || len(s.hook) != 1 {
		t.Fatalf("telegram %d, webhook %d", len(s.tg), len(s.hook))
	}
	var a Alert
	_ = json.Unmarshal(s.hook[0], &a)
	if a.Count != 51 || a.TopIPs[0] != "203.0.113.9 (50)" || a.Node != "hn-01" || a.SiteName != "shop.vn" {
		t.Fatalf("alert = %+v", a)
	}
	if s.sigs[0] != Sign("s3cret", s.hook[0]) {
		t.Fatal("bad webhook signature")
	}
	if txt := s.tg[0]["text"].(string); !strings.Contains(txt, "Tấn công web") || !strings.Contains(txt, "<b>51</b>") {
		t.Fatalf("telegram text = %s", txt)
	}

	// More events within the interval are held back...
	n.Observe(ev("waf", "203.0.113.9", "/"))
	n.Flush(ctx)
	if len(s.tg) != 1 {
		t.Fatal("alert sent before the interval elapsed")
	}
	// ...and summarised once it has passed.
	*now = now.Add(6 * time.Minute)
	n.Flush(ctx)
	if len(s.tg) != 2 {
		t.Fatal("summary not sent after the interval")
	}
	// Nothing new: no message.
	*now = now.Add(10 * time.Minute)
	n.Flush(ctx)
	if len(s.tg) != 2 {
		t.Fatal("empty alert sent")
	}
}

func TestTextEscapesAttackerInput(t *testing.T) {
	a := Alert{Node: "n", SiteName: "<b>site</b>", Kind: "waf", Count: 1, Since: time.Now(),
		Sample: &events.Event{Method: "GET", Host: "h", URI: "/<script>alert(1)</script>"}}
	txt := a.Text()
	if strings.Contains(txt, "<script>") || strings.Contains(txt, "<b>site</b>") {
		t.Fatalf("unescaped: %s", txt)
	}
}

func TestSendTestAndErrors(t *testing.T) {
	s := &sink{}
	n, _ := newNotifier(t, s)
	if err := n.SendTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.tg[0]["text"].(string), "thử nghiệm") {
		t.Fatal("test message")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "nope", 500) }))
	defer bad.Close()
	n.cfg.Webhooks = []Webhook{{URL: bad.URL}}
	if err := n.SendTest(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("expected delivery error, got %v", err)
	}
}

func TestEventsHook(t *testing.T) {
	l, _ := events.New(10, "")
	var got []string
	l.OnAdd(func(e events.Event) { got = append(got, e.Kind) })
	l.Add(events.Event{Kind: "waf"})
	if len(got) != 1 {
		t.Fatal("observer not called")
	}
}
