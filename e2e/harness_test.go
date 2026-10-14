package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Binaries

type binaries struct {
	waf, hcw, hcwctl string
}

// repoRoot is the repository checkout this module lives in.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"waf", "cluster", "ctl"} {
		if _, err := os.Stat(filepath.Join(root, m, "go.mod")); err != nil {
			t.Fatalf("%s/go.mod not found next to e2e/ (run the suite from the repository): %v", m, err)
		}
	}
	return root
}

// buildBinaries compiles hcw-waf, hcw and hcwctl from the repository into
// dir, in parallel.
func buildBinaries(t *testing.T, dir string) binaries {
	t.Helper()
	root := repoRoot(t)
	b := binaries{
		waf:    filepath.Join(dir, "hcw-waf"),
		hcw:    filepath.Join(dir, "hcw"),
		hcwctl: filepath.Join(dir, "hcwctl"),
	}
	targets := []struct{ module, pkg, out string }{
		{"waf", "./cmd/hcw-waf", b.waf},
		{"cluster", "./cmd/hcw", b.hcw},
		{"ctl", "./cmd/hcwctl", b.hcwctl},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, len(targets))
	for i, tg := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.CommandContext(ctx, "go", "build", "-o", tg.out, tg.pkg)
			cmd.Dir = filepath.Join(root, tg.module)
			out, err := cmd.CombinedOutput()
			if err != nil {
				errs[i] = fmt.Errorf("go build %s (in %s/): %v\n%s", tg.pkg, tg.module, err, out)
			}
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
	t.Logf("built hcw-waf, hcw, hcwctl in %s", time.Since(start).Round(time.Millisecond))
	return b
}

// ---------------------------------------------------------------------------
// Processes

// childEnv is the environment of the started processes: proxies are removed
// so loopback traffic never leaves the machine.
func childEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(k) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
			continue
		}
		if strings.HasPrefix(k, "HCWCTL_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

type proc struct {
	name    string
	logPath string
	extra   []string // more log files shown on failure (e.g. access logs)
	cmd     *exec.Cmd
	done    chan struct{}
	err     error // exit status, valid after done is closed
}

func (p *proc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// tailFile returns the last n lines of a log file.
func tailFile(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return "(no log: " + err.Error() + ")"
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return strings.Join(lines, "\n")
}

type cluster struct {
	t     *testing.T
	dir   string
	procs []*proc
}

// start launches a long-running process whose output goes to <dir>/<name>.log.
// It is stopped (SIGTERM, then SIGKILL after 5s) when the test ends.
func (c *cluster) start(name, bin string, args ...string) *proc {
	c.t.Helper()
	logPath := filepath.Join(c.dir, name+".log")
	lf, err := os.Create(logPath)
	if err != nil {
		c.t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = c.dir
	cmd.Env = childEnv()
	cmd.Stdout, cmd.Stderr = lf, lf
	if err := cmd.Start(); err != nil {
		lf.Close()
		c.t.Fatalf("start %s: %v", name, err)
	}
	p := &proc{name: name, logPath: logPath, cmd: cmd, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		lf.Close()
		close(p.done)
	}()
	c.procs = append(c.procs, p)
	c.t.Cleanup(func() {
		if p.exited() {
			return
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-p.done
		}
	})
	return p
}

// dumpLogs prints the tail of every process log; called when the test fails.
func (c *cluster) dumpLogs() {
	for _, p := range c.procs {
		state := "running"
		if p.exited() {
			state = fmt.Sprintf("exited: %v", p.err)
		}
		c.t.Logf("----- %s (pid %d, %s), last lines of %s -----\n%s", p.name, p.cmd.Process.Pid, state, p.logPath, tailFile(p.logPath, 40))
		for _, f := range p.extra {
			c.t.Logf("----- %s: last lines of %s -----\n%s", p.name, f, tailFile(f, 15))
		}
	}
}

// eventually polls f every 150ms until it returns nil, the timeout expires or
// one of the cluster processes dies. It returns the last error.
func (c *cluster) eventually(timeout time.Duration, what string, f func() error) error {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for {
		if last = f(); last == nil {
			return nil
		}
		for _, p := range c.procs {
			if p.exited() {
				return fmt.Errorf("%s: process %s exited (%v) while waiting; last error: %w", what, p.name, p.err, last)
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: not reached within %s; last error: %w", what, timeout, last)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// must is eventually that fails the test.
func (c *cluster) must(t *testing.T, timeout time.Duration, what string, f func() error) {
	t.Helper()
	if err := c.eventually(timeout, what, f); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// PKI

type pki struct {
	caFile, certFile, keyFile string
	pool                      *x509.CertPool
}

// newPKI creates a CA and one server certificate valid for the loopback
// addresses used by the suite (controller and engine management APIs).
func newPKI(t *testing.T, dir string) *pki {
	t.Helper()
	serial := func() *big.Int {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "HiTechCloud WAF e2e CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "e2e server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p := &pki{
		caFile:   filepath.Join(dir, "ca.crt"),
		certFile: filepath.Join(dir, "server.crt"),
		keyFile:  filepath.Join(dir, "server.key"),
		pool:     x509.NewCertPool(),
	}
	p.pool.AddCert(caCert)
	writeFile(t, p.caFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})))
	writeFile(t, p.certFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeFile(t, p.keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))
	return p
}

// ---------------------------------------------------------------------------
// Small helpers

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func randomToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// freeTCPPort returns a port that is currently free on every given host.
func freeTCPPort(t *testing.T, hosts ...string) int {
	t.Helper()
	for range 50 {
		l, err := net.Listen("tcp", net.JoinHostPort(hosts[0], "0"))
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		ok := true
		var others []net.Listener
		for _, h := range hosts[1:] {
			o, err := net.Listen("tcp", net.JoinHostPort(h, fmt.Sprint(port)))
			if err != nil {
				ok = false
				break
			}
			others = append(others, o)
		}
		for _, o := range others {
			o.Close()
		}
		l.Close()
		if ok {
			return port
		}
	}
	t.Fatalf("no free TCP port on %v", hosts)
	return 0
}

// freeUDPTCPPort returns a port free for both UDP and TCP on host (DNS).
func freeUDPTCPPort(t *testing.T, host string) int {
	t.Helper()
	for range 50 {
		u, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatal(err)
		}
		port := u.LocalAddr().(*net.UDPAddr).Port
		l, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
		u.Close()
		if err == nil {
			l.Close()
			return port
		}
	}
	t.Fatalf("no free UDP+TCP port on %s", host)
	return 0
}

// ---------------------------------------------------------------------------
// HTTP

type httpAPI struct {
	name   string
	base   string
	header string // auth header name
	value  string // its value
	client *http.Client
}

func newTLSClient(pool *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// do sends a JSON request and returns the status and body.
func (a *httpAPI) do(method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, a.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(a.header, a.value)
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s %s: %w", a.name, method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return resp.StatusCode, b, err
}

// json calls the API, checks the status and decodes the body into out.
func (a *httpAPI) json(method, path string, body any, want int, out any) error {
	code, b, err := a.do(method, path, body)
	if err != nil {
		return err
	}
	if code != want {
		return fmt.Errorf("%s %s %s: HTTP %d (want %d): %s", a.name, method, path, code, want, truncate(b, 400))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s %s %s: decode %s: %w", a.name, method, path, truncate(b, 200), err)
	}
	return nil
}

func truncate(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// siteRequest sends a plain HTTP request to a WAF site listener with the
// given Host header.
func siteRequest(addr, host, pathAndQuery string) (int, string, error) {
	c := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+pathAndQuery, nil)
	if err != nil {
		return 0, "", err
	}
	req.Host = host
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) hcw-e2e")
	req.Header.Set("Accept", "text/html,*/*")
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b), nil
}

// rawHTTP writes a request line verbatim (no client-side path cleaning) and
// returns the response status code.
func rawHTTP(addr, host, target string) (int, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 hcw-e2e\r\nAccept: */*\r\nConnection: close\r\n\r\n", target, host)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// upstream is the origin behind the WAF: it answers every request and
// remembers the paths it saw.
type upstream struct {
	addr string
	mu   sync.Mutex
	seen []string
}

const upstreamMarker = "hello from the e2e upstream"

func startUpstream(t *testing.T) *upstream {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &upstream{addr: l.Addr().String()}
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u.mu.Lock()
			u.seen = append(u.seen, r.URL.RequestURI())
			u.mu.Unlock()
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "%s: %s %s host=%s\n", upstreamMarker, r.Method, r.URL.RequestURI(), r.Host)
		}),
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return u
}

// sawPrefix reports whether the upstream received a request whose URI starts
// with prefix.
func (u *upstream) sawPrefix(prefix string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, s := range u.seen {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}
