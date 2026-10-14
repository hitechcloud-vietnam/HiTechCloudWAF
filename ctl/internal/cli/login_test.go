package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func readConfig(t *testing.T, path string) *Config {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func TestLoginTokenFile(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/me", map[string]any{"username": "api-token", "role": "admin", "account": false})
	ta := newTestApp(t)
	tokFile := writeFile(t, "token", testToken+"\n")

	out := ta.mustRun("login", "--url", f.srv.URL, "--token-file", tokFile, "--ca", f.caFile)
	contains(t, out, "Logged in to "+f.srv.URL, "api-token", `Profile "default"`)

	r := f.last("GET /api/open/me")
	if got := r.Header.Get(tokenHeader); got != testToken {
		t.Errorf("token header = %q", got)
	}
	if r.Header.Get(sessionHeader) != "" {
		t.Error("session header sent with a token profile")
	}

	cfg := readConfig(t, ta.cfgPath)
	p := cfg.Profiles["default"]
	if cfg.Current != "default" || p == nil || p.Token != testToken || p.CAFile != f.caFile || p.Session != "" {
		t.Fatalf("saved config = %+v / %+v", cfg, p)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(ta.cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("config mode = %v, want 0600", st.Mode().Perm())
		}
		dst, _ := os.Stat(filepath.Dir(ta.cfgPath))
		if dst.Mode().Perm() != 0o700 {
			t.Errorf("config dir mode = %v, want 0700", dst.Mode().Perm())
		}
	}

	// The saved profile is used by later commands.
	f.ok("GET /api/open/site", `{"data":[],"total":0}`)
	ta.mustRun("sites", "list")
	if got := f.last("GET /api/open/site").Header.Get(tokenHeader); got != testToken {
		t.Errorf("sites list token header = %q", got)
	}
}

func TestLoginRejectsBadToken(t *testing.T) {
	f := newFake(t)
	ta := newTestApp(t)
	ta.env["HCWCTL_TOKEN"] = "wrong-token"
	errOut := ta.wantExit(1, "login", "--url", f.srv.URL, "--ca", f.caFile)
	contains(t, errOut, "credentials rejected", "401")
	if _, err := os.Stat(ta.cfgPath); err == nil {
		t.Error("config saved despite rejected credentials")
	}
}

func TestLoginPasswordAndOTP(t *testing.T) {
	f := newFake(t)
	f.handle("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch {
		case in["username"] != "alice" || in["password"] != "hunter2-password":
			envelope(w, 401, nil, "unauthorized", "invalid user name or password")
		case in["otp"] == "":
			envelope(w, 401, nil, "otp_required", "two-factor code required")
		case in["otp"] != "123456":
			envelope(w, 401, nil, "unauthorized", "invalid code")
		default:
			envelope(w, 200, map[string]any{"token": testSession, "username": "alice", "role": "viewer", "expires": "2030-01-01T00:00:00Z"}, "", "")
		}
	})
	f.ok("GET /api/open/me", map[string]any{"username": "alice", "role": "viewer", "account": true})
	ta := newTestApp(t)
	ta.env["HCWCTL_PASSWORD"] = "hunter2-password"
	ta.stdin = "123456\n"

	out := ta.mustRun("--profile", "prod", "login", "--url", f.srv.URL, "--user", "alice", "--ca", f.caFile)
	contains(t, out, "alice (viewer, session)", `Profile "prod"`)
	contains(t, ta.err.String(), "Two-factor code")
	if n := len(f.requests("POST /api/auth/login")); n != 2 {
		t.Errorf("login calls = %d, want 2 (password, then OTP)", n)
	}
	if got := f.last("GET /api/open/me").Header.Get(sessionHeader); got != testSession {
		t.Errorf("session header = %q", got)
	}
	cfg := readConfig(t, ta.cfgPath)
	p := cfg.Profiles["prod"]
	if p == nil || p.Session != testSession || p.Token != "" || p.User != "alice" || cfg.Current != "prod" {
		t.Fatalf("saved = %+v", p)
	}
	if strings.Contains(mustRead(t, ta.cfgPath), "hunter2") {
		t.Error("password saved in the config")
	}

	// Password read from stdin when the environment has none.
	ta2 := newTestApp(t)
	ta2.stdin = "hunter2-password\n123456\n"
	ta2.mustRun("login", "--url", f.srv.URL, "--user", "alice", "--ca", f.caFile)
	contains(t, ta2.err.String(), "Password for alice")

	// Logout ends the session and forgets the profile.
	f.ok("POST /api/auth/logout", nil)
	ta.mustRun("logout", "--profile", "prod")
	if got := f.last("POST /api/auth/logout").Header.Get(sessionHeader); got != testSession {
		t.Errorf("logout session header = %q", got)
	}
	if _, ok := readConfig(t, ta.cfgPath).Profiles["prod"]; ok {
		t.Error("profile kept after logout")
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLoginWrongPassword(t *testing.T) {
	f := newFake(t)
	f.fail("POST /api/auth/login", 401, "unauthorized", "invalid user name or password")
	ta := newTestApp(t)
	ta.env["HCWCTL_PASSWORD"] = "nope"
	contains(t, ta.wantExit(1, "login", "--url", f.srv.URL, "--user", "bob", "--ca", f.caFile), "login failed", "invalid user name or password")
}

func TestInsecureOnlyLoopback(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1": true, "127.10.0.1": true, "::1": true, "localhost": true, "LOCALHOST": true,
		"10.0.0.1": false, "example.com": false, "localhost.example.com": false, "0.0.0.0": false, "192.168.1.1": false,
	} {
		if got := isLoopback(host); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", host, got, want)
		}
	}

	ta := newTestApp(t)
	ta.env["HCWCTL_TOKEN"] = testToken
	errOut := ta.wantExit(2, "login", "--url", "https://waf.example.com:9443", "--insecure")
	contains(t, errOut, "--insecure is only allowed for loopback hosts", "--ca")

	// A saved insecure profile cannot be redirected to a remote host.
	f := newFake(t)
	f.ok("GET /api/open/me", map[string]any{"username": "api-token", "role": "admin"})
	ta.mustRun("login", "--url", f.srv.URL, "--insecure") // 127.0.0.1: allowed
	f.ok("GET /api/open/site", `{"data":[],"total":0}`)
	ta.mustRun("sites", "list")
	ta.env["HCWCTL_URL"] = "https://10.1.2.3:9443"
	contains(t, ta.wantExit(2, "sites", "list"), "only allowed for loopback")

	contains(t, ta.wantExit(2, "login", "--url", f.srv.URL, "--insecure", "--ca", f.caFile), "mutually exclusive")
}

func TestTLSVerifiedByDefault(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/me", map[string]any{"username": "api-token", "role": "admin"})
	ta := newTestApp(t)
	ta.env["HCWCTL_TOKEN"] = testToken
	errOut := ta.wantExit(1, "login", "--url", f.srv.URL)
	contains(t, errOut, "certificate", "--ca")
	if len(f.requests("")) != 0 {
		t.Error("request reached the server without a trusted certificate")
	}
	// A CA that is not the server's is refused too.
	contains(t, ta.wantExit(1, "login", "--url", f.srv.URL, "--ca", otherCA(t)), "certificate")
	contains(t, ta.wantExit(1, "login", "--url", f.srv.URL, "--ca", writeFile(t, "junk.pem", "junk")), "no PEM certificate")
}

func TestPlainHTTPRefused(t *testing.T) {
	ta := newTestApp(t)
	ta.env["HCWCTL_TOKEN"] = testToken
	contains(t, ta.wantExit(2, "login", "--url", "http://127.0.0.1:9443"), "only https://")
}

func TestEnvOverridesWithoutConfig(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/site", `{"data":[],"total":0}`)
	ta := newTestApp(t)
	contains(t, ta.wantExit(1, "sites", "list"), "not logged in")
	ta.env["HCWCTL_URL"] = f.srv.URL
	ta.env["HCWCTL_TOKEN"] = testToken
	// The certificate is not trusted without a CA.
	contains(t, ta.wantExit(1, "sites", "list"), "certificate")
	ta.env["HCWCTL_CA"] = f.caFile
	ta.mustRun("sites", "list")
	delete(ta.env, "HCWCTL_CA")
	ta.loggedIn(f)
	ta.env["HCWCTL_TOKEN"] = "env-token"
	ta.wantExit(1, "sites", "list")
	if got := f.last("GET /api/open/site").Header.Get(tokenHeader); got != "env-token" {
		t.Errorf("HCWCTL_TOKEN not used: header %q", got)
	}
}

func TestProfiles(t *testing.T) {
	a, b := newFake(t), newFake(t)
	for _, f := range []*fakeAPI{a, b} {
		f.ok("GET /api/open/me", map[string]any{"username": "api-token", "role": "admin"})
		f.ok("GET /api/open/site", `{"data":[],"total":0}`)
	}
	ta := newTestApp(t)
	ta.env["HCWCTL_TOKEN"] = testToken
	ta.mustRun("login", "--profile", "a", "--url", a.srv.URL, "--ca", a.caFile)
	ta.mustRun("login", "--profile", "b", "--url", b.srv.URL, "--ca", b.caFile)
	delete(ta.env, "HCWCTL_TOKEN")

	ta.mustRun("sites", "list") // current = b
	if len(b.requests("GET /api/open/site")) != 1 || len(a.requests("GET /api/open/site")) != 0 {
		t.Error("current profile not used")
	}
	ta.mustRun("sites", "list", "--profile", "a")
	if len(a.requests("GET /api/open/site")) != 1 {
		t.Error("--profile a not used")
	}
	out := ta.mustRun("profiles")
	contains(t, out, "a ", "b ", a.srv.URL, b.srv.URL, "api-token")
	ta.mustRun("profiles", "use", "a")
	if readConfig(t, ta.cfgPath).Current != "a" {
		t.Error("profiles use did not switch")
	}
	contains(t, ta.wantExit(1, "sites", "list", "--profile", "nope"), `no profile "nope"`)
}

func TestLooseConfigPermissionsWarn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	f := newFake(t)
	f.ok("GET /api/open/site", `{"data":[],"total":0}`)
	ta := newTestApp(t).loggedIn(f)
	if err := os.Chmod(ta.cfgPath, 0o644); err != nil {
		t.Fatal(err)
	}
	ta.mustRun("sites", "list")
	contains(t, ta.err.String(), "readable by other users", "chmod 600")
}
