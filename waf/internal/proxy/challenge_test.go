package proxy

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (h *harness) do(t *testing.T, method, host, path string, form url.Values, cookies []*http.Cookie, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", h.port, path), body)
	req.Host = host
	req.Header.Set("User-Agent", browser["User-Agent"])
	req.Header.Set("Accept", "text/html")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

var nonceRe = regexp.MustCompile(`name="nonce" value="([^"]+)"`)

func solve(nonce string, bits int) string {
	for c := 0; ; c++ {
		if leadingZeroBits(sha256.Sum256([]byte(nonce+":"+strconv.Itoa(c)))) >= bits {
			return strconv.Itoa(c)
		}
	}
}

func TestBotChallengeFlow(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"bot.example.vn"},
		Bot: model.BotChallenge{Enabled: true, Difficulty: 12, ExcludePaths: []string{"/api/"}}})

	resp, page := h.do(t, "GET", "bot.example.vn", "/shop?x=1", nil, nil, nil)
	if resp.StatusCode != 403 || !strings.Contains(page, "Đang kiểm tra trình duyệt") {
		t.Fatalf("expected challenge page, got %d", resp.StatusCode)
	}
	m := nonceRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no nonce in page")
	}
	nonce := m[1]

	// Wrong answer.
	wrong := 0
	for leadingZeroBits(sha256.Sum256([]byte(nonce+":"+strconv.Itoa(wrong)))) >= 12 {
		wrong++
	}
	if r, _ := h.do(t, "POST", "bot.example.vn", "/.hcw/verify", url.Values{"nonce": {nonce}, "counter": {strconv.Itoa(wrong)}, "return": {"/shop?x=1"}}, nil, nil); r.StatusCode != 403 {
		t.Fatalf("wrong counter accepted: %d", r.StatusCode)
	}
	// Forged nonce.
	if r, _ := h.do(t, "POST", "bot.example.vn", "/.hcw/verify", url.Values{"nonce": {"1.2.3"}, "counter": {solve("1.2.3", 12)}}, nil, nil); r.StatusCode != 403 {
		t.Fatalf("forged nonce accepted: %d", r.StatusCode)
	}

	r, _ := h.do(t, "POST", "bot.example.vn", "/.hcw/verify", url.Values{"nonce": {nonce}, "counter": {solve(nonce, 12)}, "return": {"/shop?x=1"}}, nil, nil)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/shop?x=1" || len(r.Cookies()) != 1 {
		t.Fatalf("verify: %d %v", r.StatusCode, r.Header)
	}
	pass := r.Cookies()
	if !pass[0].HttpOnly {
		t.Fatal("cookie must be HttpOnly")
	}
	if r, body := h.do(t, "GET", "bot.example.vn", "/shop?x=1", nil, pass, nil); r.StatusCode != 200 || !strings.Contains(body, "origin ok") {
		t.Fatalf("with pass: %d", r.StatusCode)
	}
	// Tampered cookie.
	bad := []*http.Cookie{{Name: pass[0].Name, Value: pass[0].Value + "x"}}
	if r, _ := h.do(t, "GET", "bot.example.vn", "/", nil, bad, nil); r.StatusCode != 403 {
		t.Fatalf("tampered cookie accepted: %d", r.StatusCode)
	}
	// Excluded path.
	if r, _ := h.do(t, "GET", "bot.example.vn", "/api/orders", nil, nil, nil); r.StatusCode != 200 {
		t.Fatalf("excluded path challenged: %d", r.StatusCode)
	}
}

func TestBotPassBoundToClientIP(t *testing.T) {
	lb, _ := model.ParseCIDR("127.0.0.1")
	h := newHarness(t, nil, model.Site{ServerNames: []string{"b.example.vn"}, Bot: model.BotChallenge{Enabled: true, Difficulty: 10}})
	h.eng.opt.TrustedProxies = append(h.eng.opt.TrustedProxies, lb)
	from := func(ip string) map[string]string { return map[string]string{"X-Forwarded-For": ip} }

	_, page := h.do(t, "GET", "b.example.vn", "/", nil, nil, from("198.51.100.1"))
	nonce := nonceRe.FindStringSubmatch(page)[1]
	r, _ := h.do(t, "POST", "b.example.vn", "/.hcw/verify", url.Values{"nonce": {nonce}, "counter": {solve(nonce, 10)}}, nil, from("198.51.100.1"))
	pass := r.Cookies()
	if r, _ := h.do(t, "GET", "b.example.vn", "/", nil, pass, from("198.51.100.1")); r.StatusCode != 200 {
		t.Fatalf("same IP: %d", r.StatusCode)
	}
	if r, _ := h.do(t, "GET", "b.example.vn", "/", nil, pass, from("203.0.113.5")); r.StatusCode != 403 {
		t.Fatalf("pass reused from another IP: %d", r.StatusCode)
	}
	// A nonce issued to one IP cannot be redeemed from another.
	_, page = h.do(t, "GET", "b.example.vn", "/", nil, nil, from("198.51.100.1"))
	nonce = nonceRe.FindStringSubmatch(page)[1]
	if r, _ := h.do(t, "POST", "b.example.vn", "/.hcw/verify", url.Values{"nonce": {nonce}, "counter": {solve(nonce, 10)}}, nil, from("203.0.113.5")); r.StatusCode != 403 {
		t.Fatalf("nonce redeemed from another IP: %d", r.StatusCode)
	}
}

func TestAuthChallengeFlow(t *testing.T) {
	site := model.Site{ServerNames: []string{"a.example.vn"}, Mode: model.ModeOff, Auth: model.AuthChallenge{Enabled: true, Password: "Bi-mat-2026!"}}
	h := newHarness(t, nil, site)

	if r, page := h.do(t, "GET", "a.example.vn", "/admin", nil, nil, nil); r.StatusCode != 401 || !strings.Contains(page, `name="password"`) {
		t.Fatalf("expected login page: %d", r.StatusCode)
	}
	if r, page := h.do(t, "POST", "a.example.vn", "/.hcw/auth", url.Values{"password": {"sai"}, "return": {"/admin"}}, nil, nil); r.StatusCode != 401 || !strings.Contains(page, "không đúng") {
		t.Fatalf("wrong password: %d", r.StatusCode)
	}
	r, _ := h.do(t, "POST", "a.example.vn", "/.hcw/auth", url.Values{"password": {"Bi-mat-2026!"}, "return": {"//evil.example/x"}}, nil, nil)
	if r.StatusCode != 303 || r.Header.Get("Location") != "/" {
		t.Fatalf("login/open redirect: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	pass := r.Cookies()
	if r, _ := h.do(t, "GET", "a.example.vn", "/admin", nil, pass, nil); r.StatusCode != 200 {
		t.Fatalf("with pass: %d", r.StatusCode)
	}

	// Changing the password invalidates existing passes.
	cur := h.eng.rt.Load().ports[h.port].exact["a.example.vn"].site
	cur.Auth.Password = "Mat-khau-moi-1"
	if err := cur.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := h.eng.Apply([]model.Site{cur}, nil); err != nil {
		t.Fatal(err)
	}
	if r, _ := h.do(t, "GET", "a.example.vn", "/admin", nil, pass, nil); r.StatusCode != 401 {
		t.Fatalf("old pass still valid after password change: %d", r.StatusCode)
	}
}

func TestAuthBruteForceLock(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"a.example.vn"}, Mode: model.ModeOff, Auth: model.AuthChallenge{Enabled: true, Password: "Bi-mat-2026!"}})
	for i := 0; i < 10; i++ {
		h.do(t, "POST", "a.example.vn", "/.hcw/auth", url.Values{"password": {"wrong" + strconv.Itoa(i)}}, nil, nil)
	}
	if r, _ := h.do(t, "POST", "a.example.vn", "/.hcw/auth", url.Values{"password": {"Bi-mat-2026!"}}, nil, nil); r.StatusCode != 429 {
		t.Fatalf("expected lock after 10 failures, got %d", r.StatusCode)
	}
}

func TestPasswordIsNeverStoredInClear(t *testing.T) {
	s := model.Site{ServerNames: []string{"x.vn"}, Upstreams: []string{"http://1.1.1.1"}, Auth: model.AuthChallenge{Enabled: true, Password: "Bi-mat-2026!"}}
	if err := s.Normalize(); err != nil {
		t.Fatal(err)
	}
	if s.Auth.Password != "" || !strings.HasPrefix(s.Auth.PasswordHash, "$2") {
		t.Fatalf("auth = %+v", s.Auth)
	}
	// A replicated site carries only the hash and must stay valid.
	again := s
	if err := again.Normalize(); err != nil || again.Auth.PasswordHash != s.Auth.PasswordHash {
		t.Fatalf("re-normalize: %v", err)
	}
}

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{"/a?b=1": "/a?b=1", "//evil.com": "/", "/\\evil.com": "/", "https://evil.com": "/", "": "/", "/x\r\nSet-Cookie: a": "/"} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q", in, got)
		}
	}
}
