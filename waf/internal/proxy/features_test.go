package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

type fakeACME struct {
	cert  *tls.Certificate
	asked []string
}

func (f *fakeACME) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.asked = append(f.asked, h.ServerName)
	return f.cert, nil
}

func (f *fakeACME) HTTPHandler(http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "acme-token-for-"+r.Host) })
}

func TestAutoTLSAndHSTS(t *testing.T) {
	ev, _ := events.New(10, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng := New(ctx, Options{Bind: "127.0.0.1", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Events: ev})
	defer eng.Shutdown(context.Background())
	crt, key := selfSigned(t, "auto.example.vn")
	kp, _ := tls.X509KeyPair([]byte(crt), []byte(key))
	fake := &fakeACME{cert: &kp}
	eng.SetCertProvider(fake)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer origin.Close()

	pTLS, pHTTP := freePort(t), freePort(t)
	site := model.Site{ID: 1, ServerNames: []string{"auto.example.vn"}, Ports: []string{fmt.Sprint(pHTTP), fmt.Sprintf("%d_ssl", pTLS)},
		Upstreams: []string{origin.URL}, Mode: model.ModeOff, AutoTLS: true, HSTS: true}
	if err := site.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := eng.Apply([]model.Site{site}, nil); err != nil {
		t.Fatal(err)
	}

	if err := eng.ACMEHostPolicy(ctx, "auto.example.vn"); err != nil {
		t.Fatalf("policy rejected own name: %v", err)
	}
	if err := eng.ACMEHostPolicy(ctx, "evil.example.com"); err == nil {
		t.Fatal("policy accepted a foreign name")
	}

	// HTTP-01 challenge is answered by the provider on the plain port.
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/.well-known/acme-challenge/abc", pHTTP), nil)
	req.Host = "auto.example.vn"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "acme-token-for-auto.example.vn" {
		t.Fatalf("challenge body %q", b)
	}

	// TLS uses the provider's certificate and HSTS is added.
	client := &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{ServerName: "auto.example.vn", InsecureSkipVerify: true}}} //nolint:gosec // test
	req, _ = http.NewRequest("GET", fmt.Sprintf("https://127.0.0.1:%d/", pTLS), nil)
	req.Host = "auto.example.vn"
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(fake.asked) == 0 || fake.asked[0] != "auto.example.vn" {
		t.Fatalf("provider not used: %v", fake.asked)
	}
	if !strings.HasPrefix(resp.Header.Get("Strict-Transport-Security"), "max-age=") {
		t.Fatalf("HSTS missing: %v", resp.Header)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("expected HTTP/2 over TLS, got %s", resp.Proto)
	}
	// No HSTS on plain HTTP.
	req, _ = http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", pHTTP), nil)
	req.Host = "auto.example.vn"
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS sent over plain HTTP")
	}
}

func TestAutoTLSRejectsWildcards(t *testing.T) {
	s := model.Site{ServerNames: []string{"*.example.vn"}, Ports: []string{"443_ssl"}, Upstreams: []string{"http://1.1.1.1"}, AutoTLS: true}
	if err := s.Normalize(); err == nil {
		t.Fatal("wildcard accepted for auto_tls")
	}
}

func TestCustomRules(t *testing.T) {
	rule := `SecRule ARGS:debug "@streq 1" "id:1001,phase:1,deny,status:403,log,msg:'debug mode blocked'"`
	if err := ValidateRules(rule); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, nil, model.Site{ServerNames: []string{"c.example.vn"}, CustomRules: rule})
	if code, _ := h.get(t, "c.example.vn", "/?debug=1", browser); code != 403 {
		t.Fatalf("custom rule did not block: %d", code)
	}
	if code, _ := h.get(t, "c.example.vn", "/?debug=0", browser); code != 200 {
		t.Fatalf("custom rule blocked benign: %d", code)
	}
	ev := h.ev.Latest(1, 0)[0]
	if len(ev.Rules) == 0 || ev.Rules[0].ID != 1001 {
		t.Fatalf("event = %+v", ev)
	}

	for _, bad := range []string{
		"Include /etc/passwd",
		`SecRule REMOTE_ADDR "@ipMatchFromFile /etc/hosts" "id:5,deny"`,
		`SecRule ARGS "@rx x" "id:942100,deny"`,
	} {
		s := model.Site{ServerNames: []string{"x.vn"}, Upstreams: []string{"http://1.1.1.1"}, CustomRules: bad}
		if err := s.Normalize(); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if err := ValidateRules(`SecRule ARGS "@nosuchop x" "id:7,deny"`); err == nil {
		t.Error("invalid operator accepted")
	}
}
