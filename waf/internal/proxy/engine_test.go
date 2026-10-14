package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type harness struct {
	eng    *Engine
	ev     *events.Log
	port   int
	seen   chan http.Header
	origin *httptest.Server
}

func newHarness(t *testing.T, trusted []*net.IPNet, sites ...model.Site) *harness {
	t.Helper()
	h := &harness{seen: make(chan http.Header, 100)}
	h.origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case h.seen <- r.Header.Clone():
		default:
		}
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "origin ok host=%s body=%d", r.Host, len(b))
	}))
	t.Cleanup(h.origin.Close)
	h.ev, _ = events.New(100, "")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.eng = New(ctx, Options{Bind: "127.0.0.1", TrustedProxies: trusted, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Events: h.ev})
	t.Cleanup(func() { h.eng.Shutdown(context.Background()) })
	h.port = freePort(t)
	for i := range sites {
		sites[i].ID = i + 1
		if len(sites[i].Ports) == 0 {
			sites[i].Ports = []string{fmt.Sprint(h.port)}
		}
		if len(sites[i].Upstreams) == 0 {
			sites[i].Upstreams = []string{h.origin.URL}
		}
		if err := sites[i].Normalize(); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.eng.Apply(sites, nil); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) get(t *testing.T, host, path string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d%s", h.port, path), nil)
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

var browser = map[string]string{"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0", "Accept": "text/html"}

func TestBlocksAttacksAndPassesBenign(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"shop.example.vn"}})

	if code, body := h.get(t, "shop.example.vn", "/products?id=42&q=ao+thun", browser); code != 200 || !strings.Contains(body, "origin ok") {
		t.Fatalf("benign request: %d %s", code, body)
	}
	attacks := map[string]string{
		"sqli":      "/products?id=" + url.QueryEscape("1' UNION SELECT username,password FROM users--"),
		"xss":       "/search?q=" + url.QueryEscape("<script>alert(document.cookie)</script>"),
		"traversal": "/download?f=" + url.QueryEscape("../../../../etc/passwd"),
		"rce":       "/ping?host=" + url.QueryEscape("127.0.0.1; cat /etc/passwd"),
	}
	for name, path := range attacks {
		code, body := h.get(t, "shop.example.vn", path, browser)
		if code != http.StatusForbidden || !strings.Contains(body, "HiTechCloud WAF") {
			t.Errorf("%s not blocked: %d", name, code)
		}
	}
	ev := h.ev.Latest(10, 0)
	if len(ev) != len(attacks) || len(ev[0].Rules) == 0 || ev[0].Kind != "waf" {
		t.Fatalf("events = %+v", ev)
	}
}

func TestMonitorModeLogsOnly(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"m.example.vn"}, Mode: model.ModeMonitor})
	code, _ := h.get(t, "m.example.vn", "/?id="+url.QueryEscape("1 OR 1=1 UNION SELECT password FROM users"), browser)
	if code != 200 {
		t.Fatalf("monitor mode blocked: %d", code)
	}
	ev := h.ev.Latest(10, 0)
	if len(ev) != 1 || ev[0].Action != "monitor" {
		t.Fatalf("events = %+v", ev)
	}
}

func TestRoutingRateLimitAndACL(t *testing.T) {
	h := newHarness(t, nil,
		model.Site{ServerNames: []string{"*.example.vn"}, Mode: model.ModeOff, RateLimit: model.RateLimit{Requests: 3, WindowSec: 60, BlockSec: 60}},
		model.Site{ServerNames: []string{"admin.example.vn"}, Mode: model.ModeOff, IPAllow: []string{"10.0.0.0/8"}},
		model.Site{ServerNames: []string{"deny.example.vn"}, Mode: model.ModeOff, IPDeny: []string{"127.0.0.1"}},
	)
	if code, _ := h.get(t, "unknown.org", "/", browser); code != 404 {
		t.Fatalf("unknown host: %d", code)
	}
	for i := 0; i < 3; i++ {
		if code, _ := h.get(t, "a.example.vn", "/", browser); code != 200 {
			t.Fatalf("wildcard request %d: %d", i, code)
		}
	}
	if code, _ := h.get(t, "b.example.vn", "/", browser); code != 429 {
		t.Fatalf("rate limit not enforced: %d", code)
	}
	if code, _ := h.get(t, "admin.example.vn", "/", browser); code != 403 {
		t.Fatalf("allow list not enforced: %d", code)
	}
	if code, _ := h.get(t, "deny.example.vn", "/", browser); code != 403 {
		t.Fatalf("deny list not enforced: %d", code)
	}
	st := h.ev.Stats()
	if st[1].RateLimit != 1 || st[2].ACL != 1 || st[3].ACL != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestForwardedHeadersAndTrust(t *testing.T) {
	// Untrusted peer: spoofed X-Forwarded-For is discarded.
	h := newHarness(t, nil, model.Site{ServerNames: []string{"x.example.vn"}, Mode: model.ModeOff})
	h.get(t, "x.example.vn", "/", map[string]string{"X-Forwarded-For": "1.2.3.4"})
	got := <-h.seen
	if got.Get("X-Forwarded-For") != "127.0.0.1" || got.Get("X-Real-IP") != "127.0.0.1" {
		t.Fatalf("spoofed XFF passed: %v", got)
	}

	// Trusted load balancer: the visitor address is taken from XFF, and the
	// deny list applies to it.
	lb, _ := model.ParseCIDR("127.0.0.1")
	h2 := newHarness(t, []*net.IPNet{lb}, model.Site{ServerNames: []string{"x.example.vn"}, Mode: model.ModeOff, IPDeny: []string{"203.0.113.7"}})
	h2.get(t, "x.example.vn", "/", map[string]string{"X-Forwarded-For": "198.51.100.9"})
	got = <-h2.seen
	if got.Get("X-Real-IP") != "198.51.100.9" {
		t.Fatalf("real ip = %q", got.Get("X-Real-IP"))
	}
	if code, _ := h2.get(t, "x.example.vn", "/", map[string]string{"X-Forwarded-For": "203.0.113.7"}); code != 403 {
		t.Fatalf("deny via XFF: %d", code)
	}
}

func TestUpstreamFailover(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	h := newHarness(t, nil, model.Site{ServerNames: []string{"f.example.vn"}, Mode: model.ModeOff})
	s := h.eng.rt.Load().ports[h.port].exact["f.example.vn"].site
	s.Upstreams = []string{deadURL, h.origin.URL}
	if err := h.eng.Apply([]model.Site{s}, nil); err != nil {
		t.Fatal(err)
	}
	fails := 0
	for i := 0; i < 6; i++ {
		if code, _ := h.get(t, "f.example.vn", "/", nil); code == 502 {
			fails++
		}
	}
	if fails > 1 {
		t.Fatalf("dead upstream not taken out of rotation: %d failures", fails)
	}
}

func selfSigned(t *testing.T, name string) (string, string) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	kb, _ := x509.MarshalECPrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

func TestTLSBySNI(t *testing.T) {
	ev, _ := events.New(10, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng := New(ctx, Options{Bind: "127.0.0.1", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Events: ev})
	defer eng.Shutdown(context.Background())
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("X-Forwarded-Proto"))
	}))
	defer origin.Close()

	crtA, keyA := selfSigned(t, "a.example.vn")
	crtB, keyB := selfSigned(t, "b.example.vn")
	certs := []model.Cert{{ID: 1, Crt: crtA, Key: keyA}, {ID: 2, Crt: crtB, Key: keyB}}
	for i := range certs {
		if err := certs[i].Normalize(); err != nil {
			t.Fatal(err)
		}
	}
	p := freePort(t)
	sites := []model.Site{
		{ID: 1, ServerNames: []string{"a.example.vn"}, Ports: []string{fmt.Sprintf("%d_ssl", p)}, CertID: 1, Upstreams: []string{origin.URL}, Mode: model.ModeOff},
		{ID: 2, ServerNames: []string{"b.example.vn"}, Ports: []string{fmt.Sprintf("%d_ssl", p)}, CertID: 2, Upstreams: []string{origin.URL}, Mode: model.ModeOff},
	}
	for i := range sites {
		if err := sites[i].Normalize(); err != nil {
			t.Fatal(err)
		}
	}
	if err := eng.Apply(sites, certs); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.example.vn", "b.example.vn"} {
		conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p), &tls.Config{ServerName: name, InsecureSkipVerify: true}) //nolint:gosec // test
		if err != nil {
			t.Fatal(err)
		}
		cn := conn.ConnectionState().PeerCertificates[0].Subject.CommonName
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", name)
		b, _ := io.ReadAll(conn)
		conn.Close()
		if cn != name || !strings.HasSuffix(string(b), "https") {
			t.Fatalf("%s: got cert %s, body %q", name, cn, b)
		}
	}
}

func TestEventCarriesFindings(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"d.example.vn"}})
	h.get(t, "d.example.vn", "/?id="+url.QueryEscape("1' UNION SELECT password FROM users--"), browser)
	ev := h.ev.Latest(1, 0)[0]
	ids := map[int]bool{}
	for _, r := range ev.Rules {
		ids[r.ID] = true
	}
	if !ids[942100] || !ids[949110] || ids[901340] || len(ev.Tags) != 1 || ev.Tags[0] != "attack-sqli" {
		t.Fatalf("event = %+v", ev)
	}
}

func (h *harness) post(t *testing.T, host, ctype, body string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/api/login", h.port), strings.NewReader(body))
	req.Host = host
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", browser["User-Agent"])
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == 200 && !strings.Contains(string(b), fmt.Sprintf("body=%d", len(body))) {
		t.Fatalf("upstream did not receive the full body: %s", b)
	}
	return resp.StatusCode
}

func TestRequestBodyInspection(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"api.example.vn"}})
	benign := []struct{ ctype, body string }{
		{"application/json", `{"username":"nguyen.van.a","password":"Mật-khẩu#2026","remember":true}`},
		{"application/x-www-form-urlencoded", "username=tran.thi.b&password=abc123%21&next=%2Fdashboard"},
		{"application/json", `{"comment":"Sản phẩm tốt, giao hàng nhanh. Sẽ mua lại!","rating":5}`},
		{"application/octet-stream", strings.Repeat("A", 3<<20)}, // larger than the inspected limit
	}
	for _, b := range benign {
		if code := h.post(t, "api.example.vn", b.ctype, b.body); code != 200 {
			t.Errorf("benign %s body blocked: %d", b.ctype, code)
		}
	}
	if code := h.post(t, "api.example.vn", "application/json", `{"username":"admin' OR '1'='1' -- ","password":"x"}`); code != 403 {
		t.Errorf("SQLi in JSON body not blocked: %d", code)
	}
	if code := h.post(t, "api.example.vn", "application/x-www-form-urlencoded", "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"); code != 403 {
		t.Errorf("XSS in form body not blocked: %d", code)
	}
}

func TestDisabledRulesAndParanoia(t *testing.T) {
	attack := "/?q=" + url.QueryEscape("<script>alert(1)</script>")
	all := []int{941100, 941110, 941160, 941390}
	h := newHarness(t, nil, model.Site{ServerNames: []string{"p.example.vn"}, DisabledRules: all, AnomalyThreshold: 100})
	if code, _ := h.get(t, "p.example.vn", attack, browser); code != 200 {
		t.Fatalf("threshold 100 + disabled rules should let it pass: %d", code)
	}
	h2 := newHarness(t, nil, model.Site{ServerNames: []string{"p.example.vn"}, Paranoia: 2})
	if code, _ := h2.get(t, "p.example.vn", "/products?id=42&page=2", browser); code != 200 {
		t.Fatalf("paranoia 2 blocked a plain request: %d", code)
	}
	// PL4 is strict by design: even an argument named "id" (a Unix command)
	// scores. Sites at PL3-4 need tuning with disabled_rules.
	h4 := newHarness(t, nil, model.Site{ServerNames: []string{"p.example.vn"}, Paranoia: 4})
	if code, _ := h4.get(t, "p.example.vn", "/products?id=42&page=2", browser); code != 403 {
		t.Fatalf("paranoia 4 should block: %d", code)
	}
}
