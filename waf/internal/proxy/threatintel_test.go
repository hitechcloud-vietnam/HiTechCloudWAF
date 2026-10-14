package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/threatintel"
)

var loopback = []*net.IPNet{{IP: net.IPv4(127, 0, 0, 1).To4(), Mask: net.CIDRMask(32, 32)}}

// tiHarness serves a feed over HTTP, loads it into a real manager and runs
// the engine behind a trusted proxy (127.0.0.1) so tests pick the client
// address with X-Forwarded-For.
func tiHarness(t *testing.T, sites ...model.Site) *harness {
	t.Helper()
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "# test feed\n198.51.100.0/24 ; SBL1\n2001:db8:bad::/48\n")
	}))
	t.Cleanup(feed.Close)
	m, err := threatintel.New(threatintel.Config{Feeds: []threatintel.FeedConfig{{Name: "test-drop", URL: feed.URL}}}, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RefreshAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, loopback, sites...)
	h.eng.opt.ThreatIntel = m
	return h
}

func from(ip string, extra ...string) map[string]string {
	hdr := map[string]string{"X-Forwarded-For": ip}
	for k, v := range browser {
		hdr[k] = v
	}
	for i := 0; i+1 < len(extra); i += 2 {
		hdr[extra[i]] = extra[i+1]
	}
	return hdr
}

func TestThreatIntelBlockMonitorOff(t *testing.T) {
	h := tiHarness(t,
		model.Site{ServerNames: []string{"block.vn"}, ThreatIntel: model.ModeBlock,
			Rules: []model.PathRule{{Path: "/webhook", Action: model.RuleAllow}}},
		model.Site{ServerNames: []string{"monitor.vn"}, ThreatIntel: model.ModeMonitor},
		model.Site{ServerNames: []string{"off.vn"}})

	code, body := h.get(t, "block.vn", "/", from("198.51.100.7"))
	if code != http.StatusForbidden || !strings.Contains(body, "HiTechCloud WAF") {
		t.Fatalf("listed IP not blocked: %d", code)
	}
	ev := h.ev.Latest(1, 0)
	if len(ev) != 1 || ev[0].Kind != "threat_intel" || ev[0].Feed != "test-drop" || ev[0].Action != "block" || ev[0].ClientIP != "198.51.100.7" {
		t.Fatalf("event = %+v", ev)
	}
	if !strings.Contains(body, ev[0].ID) {
		t.Fatal("block page without event ID")
	}
	if code, _ := h.get(t, "block.vn", "/", from("2001:db8:bad::99")); code != http.StatusForbidden {
		t.Fatalf("listed IPv6 not blocked: %d", code)
	}
	if code, _ := h.get(t, "block.vn", "/", from("203.0.113.7")); code != http.StatusOK {
		t.Fatalf("clean IP blocked: %d", code)
	}
	// A path rule "allow" exempts listed clients (feed false positives).
	if code, _ := h.get(t, "block.vn", "/webhook", from("198.51.100.7")); code != http.StatusOK {
		t.Fatalf("allow rule should exempt listed IPs: %d", code)
	}

	if code, _ := h.get(t, "monitor.vn", "/", from("198.51.100.8")); code != http.StatusOK {
		t.Fatalf("monitor mode blocked: %d", code)
	}
	ev = h.ev.Latest(1, 0)
	if ev[0].Action != "monitor" || ev[0].Kind != "threat_intel" || ev[0].Feed != "test-drop" {
		t.Fatalf("monitor event = %+v", ev[0])
	}
	n := len(h.ev.Latest(100, 0))
	if code, _ := h.get(t, "off.vn", "/", from("198.51.100.9")); code != http.StatusOK {
		t.Fatalf("off mode blocked: %d", code)
	}
	if len(h.ev.Latest(100, 0)) != n {
		t.Fatal("off mode recorded an event")
	}
	st := h.ev.Stats()
	if st[1].ACL != 2 || st[2].Monitored != 1 {
		t.Fatalf("counters = %+v", st)
	}
}

func TestThreatIntelChallenge(t *testing.T) {
	h := tiHarness(t, model.Site{ServerNames: []string{"ch.vn"}, ThreatIntel: model.ThreatIntelChallenge,
		Bot: model.BotChallenge{Difficulty: 10, ExcludePaths: []string{"/api/"}}})
	listed := from("198.51.100.20")

	// Clean visitors are not challenged: the bot challenge is not enabled.
	if r, _ := h.do(t, "GET", "ch.vn", "/", nil, nil, from("203.0.113.20")); r.StatusCode != http.StatusOK {
		t.Fatalf("clean IP challenged: %d", r.StatusCode)
	}
	resp, body := h.do(t, "GET", "ch.vn", "/page", nil, nil, listed)
	m := nonceRe.FindStringSubmatch(body)
	if resp.StatusCode != http.StatusForbidden || m == nil {
		t.Fatalf("listed IP not challenged: %d", resp.StatusCode)
	}
	ev := h.ev.Latest(1, 0)
	if ev[0].Kind != "threat_intel" || ev[0].Action != "challenge" || ev[0].Feed != "test-drop" {
		t.Fatalf("event = %+v", ev[0])
	}
	if r, _ := h.do(t, "GET", "ch.vn", "/api/x", nil, nil, listed); r.StatusCode != http.StatusOK {
		t.Fatalf("excluded path challenged: %d", r.StatusCode)
	}
	form := url.Values{"nonce": {m[1]}, "counter": {solve(m[1], 10)}, "return": {"/page"}}
	resp, _ = h.do(t, "POST", "ch.vn", "/.hcw/verify", form, nil, listed)
	if resp.StatusCode != http.StatusSeeOther || len(resp.Cookies()) == 0 {
		t.Fatalf("verify: %d", resp.StatusCode)
	}
	if r, body := h.do(t, "GET", "ch.vn", "/page", nil, resp.Cookies(), listed); r.StatusCode != http.StatusOK || !strings.Contains(body, "origin ok") {
		t.Fatalf("after solving: %d", r.StatusCode)
	}
}

// fakeBots verifies Googlebot only from 66.249.66.1.
type fakeBots struct{ calls atomic.Int32 }

func (f *fakeBots) Verify(_ context.Context, ip net.IP, ua string) (string, bool) {
	f.calls.Add(1)
	return "Googlebot", strings.Contains(ua, "Googlebot") && ip.String() == "66.249.66.1"
}

func TestVerifiedBotsSkipChallengeNotWAF(t *testing.T) {
	h := newHarness(t, loopback,
		model.Site{ServerNames: []string{"seo.vn"}, Bot: model.BotChallenge{Enabled: true, AllowVerified: true}},
		model.Site{ServerNames: []string{"strict.vn"}, Bot: model.BotChallenge{Enabled: true}})
	fb := &fakeBots{}
	h.eng.opt.GoodBots = fb
	gua := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

	if code, body := h.get(t, "seo.vn", "/", from("66.249.66.1", "User-Agent", gua)); code != http.StatusOK || !strings.Contains(body, "origin ok") {
		t.Fatalf("verified Googlebot challenged: %d", code)
	}
	if code, _ := h.get(t, "seo.vn", "/", from("203.0.113.66", "User-Agent", gua)); code != http.StatusForbidden {
		t.Fatalf("fake Googlebot passed: %d", code)
	}
	if code, _ := h.get(t, "seo.vn", "/?id="+url.QueryEscape("1' UNION SELECT password FROM users--"), from("66.249.66.1", "User-Agent", gua)); code != http.StatusForbidden {
		t.Fatalf("verified bot skipped the WAF: %d", code)
	} else if ev := h.ev.Latest(1, 0); ev[0].Kind != "waf" {
		t.Fatalf("event = %+v", ev[0])
	}
	calls := fb.calls.Load()
	if code, _ := h.get(t, "strict.vn", "/", from("66.249.66.1", "User-Agent", gua)); code != http.StatusForbidden {
		t.Fatalf("allow_verified off but bot passed: %d", code)
	}
	if fb.calls.Load() != calls {
		t.Fatal("verifier called for a site without allow_verified")
	}
}
