package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testToken   = "tok-secret-0123456789"
	testSession = "sess-secret-9876543210"
)

type recorded struct {
	Method, Path string
	Query        url.Values
	Header       http.Header
	Body         []byte
}

// fakeAPI imitates the management API over TLS.
type fakeAPI struct {
	t      *testing.T
	srv    *httptest.Server
	caFile string

	mu     sync.Mutex
	reqs   []recorded
	routes map[string]http.HandlerFunc
}

func newFake(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{t: t, routes: map[string]http.HandlerFunc{}}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failures
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.caFile = filepath.Join(t.TempDir(), "ca.pem")
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	if err := os.WriteFile(f.caFile, pemCA, 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func envelope(w http.ResponseWriter, status int, data any, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	var e *string
	if code != "" {
		e = &code
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "err": e, "msg": msg})
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.reqs = append(f.reqs, recorded{r.Method, r.URL.Path, r.URL.Query(), r.Header.Clone(), body})
	h := f.routes[r.Method+" "+r.URL.Path]
	f.mu.Unlock()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if r.URL.Path != "/api/auth/login" {
		tok := r.Header.Get(tokenHeader)
		if b := r.Header.Get("Authorization"); tok == "" && strings.HasPrefix(b, "Bearer ") {
			tok = b[7:]
		}
		if tok != testToken && r.Header.Get(sessionHeader) != testSession {
			envelope(w, 401, nil, "unauthorized", "missing or invalid API token or session")
			return
		}
	}
	if h == nil {
		envelope(w, 404, nil, "not_found", "no route "+r.Method+" "+r.URL.Path)
		return
	}
	h(w, r)
}

func (f *fakeAPI) handle(route string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[route] = h
}

// ok answers route with data; data may be a JSON string.
func (f *fakeAPI) ok(route string, data any) {
	if s, isStr := data.(string); isStr && (strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")) {
		data = json.RawMessage(s)
	}
	f.handle(route, func(w http.ResponseWriter, _ *http.Request) { envelope(w, 200, data, "", "") })
}

func (f *fakeAPI) fail(route string, status int, code, msg string) {
	f.handle(route, func(w http.ResponseWriter, _ *http.Request) { envelope(w, status, nil, code, msg) })
}

func (f *fakeAPI) requests(route string) []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recorded
	for _, r := range f.reqs {
		if route == "" || r.Method+" "+r.Path == route {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeAPI) last(route string) recorded {
	f.t.Helper()
	rs := f.requests(route)
	if len(rs) == 0 {
		f.t.Fatalf("no request %s; got %v", route, f.routes)
	}
	return rs[len(rs)-1]
}

// syncBuffer is a bytes.Buffer safe for concurrent use.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}

type testApp struct {
	t       *testing.T
	cfgPath string
	env     map[string]string
	stdin   string
	out     syncBuffer
	err     syncBuffer
	poll    time.Duration
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	return &testApp{t: t, cfgPath: filepath.Join(t.TempDir(), "hcwctl", "config.json"), env: map[string]string{}}
}

// loggedIn saves a token profile for f, pinned to its certificate.
func (ta *testApp) loggedIn(f *fakeAPI) *testApp {
	ta.t.Helper()
	cfg := &Config{Current: "default", Profiles: map[string]*Profile{
		"default": {URL: f.srv.URL, Token: testToken, User: "api-token", Role: "admin", CAFile: f.caFile},
	}}
	if err := saveConfig(ta.cfgPath, cfg); err != nil {
		ta.t.Fatal(err)
	}
	return ta
}

// run executes hcwctl with fresh output buffers and returns the exit code.
func (ta *testApp) run(args ...string) int {
	return ta.runCtx(context.Background(), args...)
}

func (ta *testApp) runCtx(ctx context.Context, args ...string) int {
	ta.out.Reset()
	ta.err.Reset()
	a := &App{
		Stdin: strings.NewReader(ta.stdin), Stdout: &ta.out, Stderr: &ta.err,
		Getenv: func(k string) string { return ta.env[k] }, ConfigPath: ta.cfgPath, PollInterval: ta.poll,
	}
	code := a.Run(ctx, args)
	for _, secret := range []string{testToken, testSession, "hunter2-password"} {
		if strings.Contains(ta.out.String(), secret) || strings.Contains(ta.err.String(), secret) {
			ta.t.Errorf("hcwctl %v printed a secret:\nstdout: %s\nstderr: %s", args, ta.out.String(), ta.err.String())
		}
	}
	return code
}

func (ta *testApp) mustRun(args ...string) string {
	ta.t.Helper()
	if code := ta.run(args...); code != 0 {
		ta.t.Fatalf("hcwctl %v: exit %d\nstdout: %s\nstderr: %s", args, code, ta.out.String(), ta.err.String())
	}
	return ta.out.String()
}

func (ta *testApp) wantExit(want int, args ...string) string {
	ta.t.Helper()
	if code := ta.run(args...); code != want {
		ta.t.Fatalf("hcwctl %v: exit %d, want %d\nstdout: %s\nstderr: %s", args, code, want, ta.out.String(), ta.err.String())
	}
	return ta.err.String()
}

func contains(t *testing.T, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("output does not contain %q:\n%s", sub, s)
		}
	}
}

func decodeBody(t *testing.T, r recorded) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("%s %s body %q: %v", r.Method, r.Path, r.Body, err)
	}
	return m
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// otherCA writes a self-signed certificate unrelated to the test servers.
func otherCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "other"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, "other-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
}
