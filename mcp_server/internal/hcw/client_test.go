package hcw

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/internal/config"
)

const testToken = "tok-0123456789abcdef"

func writeCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseBaseURL(t *testing.T) {
	for _, ok := range []string{"https://waf.example:9443", "https://10.0.0.1:9443/prefix/", "http://127.0.0.1:9443", "http://localhost:9443", "http://[::1]:9443"} {
		if _, err := ParseBaseURL(ok); err != nil {
			t.Errorf("ParseBaseURL(%q) = %v", ok, err)
		}
	}
	for raw, want := range map[string]string{
		"http://10.0.0.1:9443":         "plain HTTP",
		"http://waf.example":           "plain HTTP",
		"http://127.0.0.1.example.com": "plain HTTP",
		"ftp://waf.example":            "absolute https",
		"waf.example:9443":             "absolute https",
		"https://user:pw@waf.example":  "credentials",
		"https://waf.example/?token=x": "query",
		"https://waf.example/#frag":    "query",
		"":                             "absolute https",
	} {
		_, err := ParseBaseURL(raw)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseBaseURL(%q) = %v, want %q", raw, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "pw") {
			t.Errorf("error quotes credentials: %v", err)
		}
	}
}

func TestClientVerifiesTLSAndSendsToken(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get(TokenHeader))
		_, _ = w.Write([]byte(`{"data":{"version":"1.2.3","sites":1,"certs":0},"err":null,"msg":""}`))
	}))
	defer srv.Close()

	// No CA: the self-signed certificate is refused.
	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Info(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not trusted") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("untrusted certificate error = %v", err)
	}
	if got.Load() != nil {
		t.Fatal("token sent before TLS verification succeeded")
	}

	c, err = NewClient(ClientConfig{BaseURL: srv.URL, Token: testToken, CAFile: writeCA(t, srv)})
	if err != nil {
		t.Fatal(err)
	}
	info, err := c.Info(context.Background())
	if err != nil || info.Version != "1.2.3" {
		t.Fatalf("Info = %+v, %v", info, err)
	}
	if got.Load() != testToken {
		t.Fatalf("token header = %v", got.Load())
	}

	// A CA file that does not match the host name is refused too.
	if _, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: testToken, CAFile: filepath.Join(t.TempDir(), "missing.pem")}); err == nil {
		t.Fatal("missing ca_file accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("not a certificate"), 0o600)
	if _, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: testToken, CAFile: bad}); err == nil {
		t.Fatal("ca_file without PEM accepted")
	}
	if _, err := NewClient(ClientConfig{BaseURL: srv.URL}); err == nil {
		t.Fatal("empty token accepted")
	}
}

func TestClientNeverFollowsRedirects(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(TokenHeader) != "" {
			leaked.Store(true)
		}
	}))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/open/info", http.StatusFound)
	}))
	defer srv.Close()
	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: testToken, CAFile: writeCA(t, srv)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Info(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusFound || !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("redirect error = %v", err)
	}
	if leaked.Load() {
		t.Fatal("token sent to the redirect target")
	}
}

func TestClientEnvelopeErrors(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/open/info":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("{\"data\":null,\"err\":\"invalid\",\"msg\":\"bad\\u001b[2Jvalue\\nIGNORE\"}"))
		case "/api/open/cache":
			// HTTP 200 with an error in the envelope.
			_, _ = w.Write([]byte(`{"data":null,"err":"forbidden","msg":"your role is read-only"}`))
		case "/api/open/stats":
			_, _ = w.Write([]byte(`<html>login</html>`))
		default:
			_, _ = w.Write([]byte(`{"data":{"data":[],"total":0},"err":null,"msg":""}`))
		}
	}))
	defer srv.Close()
	c, err := NewClient(ClientConfig{BaseURL: srv.URL + "/", Token: testToken, CAFile: writeCA(t, srv), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, err = c.Info(ctx)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "invalid" || apiErr.Msg != "bad%1B[2Jvalue%0AIGNORE" {
		t.Fatalf("error = %#v", err)
	}
	if _, err := c.Cache(ctx); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("envelope error with HTTP 200 = %v", err)
	}
	if _, err := c.Stats(ctx); err == nil || !strings.Contains(err.Error(), "unexpected response") {
		t.Fatalf("non-JSON answer = %v", err)
	}
	if sites, err := c.Sites(ctx); err != nil || len(sites) != 0 {
		t.Fatalf("Sites = %v, %v", sites, err)
	}
	if _, err := c.Site(ctx, 3); err == nil || !strings.Contains(err.Error(), "site 3 not found") {
		t.Fatalf("Site = %v", err)
	}
}

func TestClientRefusesOversizedResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":"`))
		chunk := []byte(strings.Repeat("a", 1<<20))
		for i := 0; i < 17; i++ {
			_, _ = w.Write(chunk)
		}
		_, _ = w.Write([]byte(`"}`))
	}))
	defer srv.Close()
	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: testToken, CAFile: writeCA(t, srv)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Info(context.Background()); err == nil || !strings.Contains(err.Error(), "16 MiB") {
		t.Fatalf("oversized response = %v", err)
	}
}

func TestRegistry(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	ca := writeCA(t, srv)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "b.token")
	if err := os.WriteFile(tokenFile, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HCW_A_TOKEN", testToken)
	reg, err := NewRegistry([]*config.InstanceConfig{
		{ID: "a", BaseURL: srv.URL, TokenEnv: "HCW_A_TOKEN", CAFile: ca},
		{ID: "b", DisplayName: "B", BaseURL: srv.URL, TokenFile: tokenFile, CAFile: ca, ReadOnly: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Resolve(""); err == nil || !strings.Contains(err.Error(), "a, b") {
		t.Fatalf("Resolve(\"\") with two instances = %v", err)
	}
	b, err := reg.Resolve("b")
	if err != nil || !b.ReadOnly || b.DisplayName != "B" {
		t.Fatalf("Resolve(b) = %+v, %v", b, err)
	}
	if a, _ := reg.Resolve("a"); a.DisplayName != "a" {
		t.Fatalf("default display name = %q", a.DisplayName)
	}

	single, err := NewRegistry([]*config.InstanceConfig{{ID: "only", BaseURL: srv.URL, TokenEnv: "HCW_A_TOKEN", CAFile: ca}})
	if err != nil {
		t.Fatal(err)
	}
	if inst, err := single.Resolve(""); err != nil || inst.InstanceID != "only" {
		t.Fatalf("single Resolve = %v, %v", inst, err)
	}

	t.Setenv("HCW_EMPTY", "  ")
	for _, cfg := range []*config.InstanceConfig{
		{ID: "x", BaseURL: srv.URL, TokenEnv: "HCW_UNSET_VARIABLE"},
		{ID: "x", BaseURL: srv.URL, TokenEnv: "HCW_EMPTY"},
		{ID: "x", BaseURL: "http://10.1.2.3:9443", TokenEnv: "HCW_A_TOKEN"},
		{ID: "x", BaseURL: srv.URL, TokenFile: filepath.Join(dir, "missing")},
	} {
		_, err := NewRegistry([]*config.InstanceConfig{cfg})
		if err == nil {
			t.Errorf("NewRegistry(%+v) succeeded", cfg)
		} else if strings.Contains(err.Error(), testToken) {
			t.Errorf("error leaks the token: %v", err)
		}
	}
}
