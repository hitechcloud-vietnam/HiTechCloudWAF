package proxy

import (
	"net/url"
	"testing"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

func TestPathRules(t *testing.T) {
	sqli := url.QueryEscape("1' UNION SELECT password FROM users--")
	h := newHarness(t, nil, model.Site{
		ServerNames: []string{"r.vn"},
		Bot:         model.BotChallenge{Enabled: true, Difficulty: 10},
		Rules: []model.PathRule{
			{Path: "/admin", Action: model.RuleDeny},
			{Path: "/webhook", Action: model.RuleAllow, IPs: []string{"127.0.0.1"}},
			{Path: "/partner", Action: model.RuleAllow, IPs: []string{"10.0.0.0/8"}},
			{Path: "/api/raw", Action: model.RuleSkipWAF},
			{Path: "/login", Exact: true, Methods: []string{"post"}, Action: model.RuleRateLimit, RateLimit: model.RateLimit{Requests: 3, WindowSec: 60}},
			{Path: "/", Action: model.RuleAllow, Methods: []string{"OPTIONS"}},
		},
	})
	// Deny.
	if r, _ := h.do(t, "GET", "r.vn", "/admin/users", nil, nil, nil); r.StatusCode != 403 {
		t.Fatalf("deny: %d", r.StatusCode)
	}
	// Whitelisted caller skips the bot challenge and the WAF.
	if r, _ := h.do(t, "GET", "r.vn", "/webhook?id="+sqli, nil, nil, nil); r.StatusCode != 200 {
		t.Fatalf("allow: %d", r.StatusCode)
	}
	// Allow rule for another network does not apply: challenge page.
	if r, _ := h.do(t, "GET", "r.vn", "/partner", nil, nil, nil); r.StatusCode != 403 {
		t.Fatalf("foreign allow rule applied: %d", r.StatusCode)
	}
	// skip_waf still requires the bot pass but not the CRS: get a pass first.
	_, page := h.do(t, "GET", "r.vn", "/", nil, nil, nil)
	nonce := nonceRe.FindStringSubmatch(page)[1]
	vr, _ := h.do(t, "POST", "r.vn", "/.hcw/verify", url.Values{"nonce": {nonce}, "counter": {solve(nonce, 10)}}, nil, nil)
	pass := vr.Cookies()
	if r, _ := h.do(t, "GET", "r.vn", "/api/raw?q="+sqli, nil, pass, nil); r.StatusCode != 200 {
		t.Fatalf("skip_waf: %d", r.StatusCode)
	}
	if r, _ := h.do(t, "GET", "r.vn", "/shop?q="+sqli, nil, pass, nil); r.StatusCode != 403 {
		t.Fatalf("WAF must still apply elsewhere: %d", r.StatusCode)
	}
	// Per-path rate limit: POST /login only.
	for i := 0; i < 3; i++ {
		if r, _ := h.do(t, "POST", "r.vn", "/login", url.Values{"u": {"a"}}, pass, nil); r.StatusCode != 200 {
			t.Fatalf("login %d: %d", i, r.StatusCode)
		}
	}
	if r, _ := h.do(t, "POST", "r.vn", "/login", url.Values{"u": {"a"}}, pass, nil); r.StatusCode != 429 {
		t.Fatalf("login rate limit: %d", r.StatusCode)
	}
	if r, _ := h.do(t, "GET", "r.vn", "/login", nil, pass, nil); r.StatusCode != 200 {
		t.Fatalf("GET /login limited: %d", r.StatusCode)
	}
	if r, _ := h.do(t, "POST", "r.vn", "/login/reset", url.Values{"u": {"a"}}, pass, nil); r.StatusCode != 200 {
		t.Fatalf("exact match leaked: %d", r.StatusCode)
	}
}

func TestRuleValidation(t *testing.T) {
	for _, r := range []model.PathRule{
		{Path: "admin", Action: model.RuleDeny},
		{Path: "/x", Action: "explode"},
		{Path: "/x", Action: model.RuleRateLimit},
		{Path: "/x", Action: model.RuleAllow, IPs: []string{"not-an-ip"}},
	} {
		s := model.Site{ServerNames: []string{"x.vn"}, Upstreams: []string{"http://1.1.1.1"}, Rules: []model.PathRule{r}}
		if err := s.Normalize(); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
}
