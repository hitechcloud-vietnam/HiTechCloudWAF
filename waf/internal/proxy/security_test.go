package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

func TestNonCanonicalPathsCannotBypassRules(t *testing.T) {
	sqli := url.QueryEscape("1' UNION SELECT password FROM users--")
	h := newHarness(t, nil, model.Site{
		ServerNames: []string{"p.vn"},
		Rules: []model.PathRule{
			{Path: "/admin", Action: model.RuleDeny},
			{Path: "/static/", Action: model.RuleAllow},
		},
	})
	for _, p := range []string{"/admin", "//admin", "/./admin", "/x/../admin", "/static/../admin", "/static/%2e%2e/login?id=" + sqli, "/static/..%2flogin", "/static\\..\\admin"} {
		if code, _ := h.get(t, "p.vn", p, browser); code != 403 && code != 400 {
			t.Errorf("%s: %d, want refused", p, code)
		}
	}
	for _, p := range []string{"/", "/static/app.js", "/a/b/", "/search?q=a%2Fb"} {
		if code, _ := h.get(t, "p.vn", p, browser); code != 200 {
			t.Errorf("%s: %d, want 200", p, code)
		}
	}
}

func TestCanonicalPath(t *testing.T) {
	for p, want := range map[string]bool{"/": true, "/a/b": true, "/a/b/": true, "*": true, "": true,
		"//a": false, "/a//b": false, "/a/./b": false, "/a/..": false, "/a\\b": false, "/.": false} {
		if got := canonicalPath(p); got != want {
			t.Errorf("canonicalPath(%q) = %v", p, got)
		}
	}
}

func TestSplitForwardedForHeaderCannotSpoofIP(t *testing.T) {
	_, lo, _ := net.ParseCIDR("127.0.0.0/8")
	h := newHarness(t, []*net.IPNet{lo}, model.Site{ServerNames: []string{"x.vn"}, IPAllow: []string{"10.9.9.9/32"}})
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", h.port), nil)
	req.Host = "x.vn"
	req.Header.Add("X-Forwarded-For", "10.9.9.9")    // sent by the client
	req.Header.Add("X-Forwarded-For", "203.0.113.7") // added by the load balancer
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("spoofed address admitted: %d", resp.StatusCode)
	}
}

func TestSafeReturnRejectsControlCharacters(t *testing.T) {
	for _, in := range []string{"/\t/evil.example", "/\n/evil", "/\\evil", "/a\x7f", "//evil"} {
		if got := safeReturn(in); got != "/" {
			t.Errorf("safeReturn(%q) = %q", in, got)
		}
	}
	if got := safeReturn("/shop?a=1#x"); got != "/shop?a=1#x" {
		t.Errorf("valid return changed: %q", got)
	}
}

func TestRateLimitGroupsIPv6Prefix(t *testing.T) {
	a, b := net.ParseIP("2001:db8:1:2::1"), net.ParseIP("2001:db8:1:2:ffff::9")
	if ipKey(a) != ipKey(b) {
		t.Fatal("addresses of one /64 must share a rate limit key")
	}
}

func TestLimiterIsBounded(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	for i := 0; i < len(l.shards)*maxShardEntries+5000; i++ {
		l.allow(fmt.Sprint(i), 10, time.Minute, time.Minute, now)
	}
	for i := range l.shards {
		if n := len(l.shards[i].m); n > maxShardEntries {
			t.Fatalf("shard %d holds %d entries", i, n)
		}
	}
}

func TestRedirectHost(t *testing.T) {
	s := &siteRT{site: model.Site{ServerNames: []string{"shop.vn", "*.shop.vn"}}}
	for in, want := range map[string]string{"shop.vn": "shop.vn", "a.shop.vn:80": "a.shop.vn", "evil.com": "shop.vn"} {
		if got := redirectHost(s, in); got != want {
			t.Errorf("redirectHost(%q) = %q, want %q", in, got, want)
		}
	}
	any := &siteRT{site: model.Site{ServerNames: []string{"_"}}}
	if got := redirectHost(any, "ev<il>"); got != "" {
		t.Errorf("invalid host kept: %q", got)
	}
}
