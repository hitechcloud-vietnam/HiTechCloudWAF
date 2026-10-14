package cli

import (
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestStats(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/stats", `{"10":{"requests":5,"blocked":1},"2":{"requests":100,"blocked":7,"monitored":3,"rate_limited":4,"acl_blocked":2,"bot_failed":1}}`)
	f.ok("GET /api/open/site", `{"data":[{"id":2,"name":"shop"},{"id":10,"name":"api"}]}`)
	ta := newTestApp(t).loggedIn(f)
	out := ta.mustRun("stats")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 {
		t.Fatalf("stats:\n%s", out)
	}
	contains(t, lines[0], "REQUESTS", "BLOCKED", "RATE LIMITED")
	contains(t, lines[1], "2", "shop", "100", "7", "3", "4")
	contains(t, lines[2], "10", "api", "5")
	contains(t, lines[3], "all", "105", "8")
	out = ta.mustRun("stats", "-o", "json")
	var m map[string]map[string]int
	if err := json.Unmarshal([]byte(out), &m); err != nil || m["2"]["requests"] != 100 {
		t.Errorf("json %v %v", m, err)
	}
}

func TestUpstreams(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/upstreams", `{"1":[{"url":"http://10.0.0.5:8080","healthy":true,"checked":true,"last_check":"2026-10-14T09:00:00Z"},
	  {"url":"http://10.0.0.6:8080","healthy":false,"checked":true,"last_error":"connection refused"}]}`)
	f.ok("GET /api/open/site", `{"data":[{"id":1,"name":"shop"}]}`)
	ta := newTestApp(t).loggedIn(f)
	out := ta.mustRun("upstreams")
	contains(t, out, "UPSTREAM", "HEALTHY", "http://10.0.0.5:8080", "yes", "http://10.0.0.6:8080", "connection refused", "shop")
	contains(t, ta.mustRun("upstreams", "-o", "json"), `"healthy": false`)
}

func TestAudit(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/audit", `{"data":[
	  {"time":"2026-10-14T09:05:00Z","user":"alice","ip":"10.0.0.1","action":"PUT /api/open/site","status":200,"detail":{"id":1}},
	  {"time":"2026-10-14T09:00:00Z","user":"bob","ip":"10.0.0.2","action":"login","status":401}]}`)
	ta := newTestApp(t).loggedIn(f)
	out := ta.mustRun("audit", "--limit", "5")
	if got := f.last("GET /api/open/audit").Query.Get("limit"); got != "5" {
		t.Errorf("limit = %q", got)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("audit:\n%s", out)
	}
	contains(t, lines[1], "bob", "login", "401")
	contains(t, lines[2], "alice", "PUT /api/open/site", "200")
	contains(t, ta.mustRun("audit", "-o", "json"), `"detail"`)
	if got := f.last("GET /api/open/audit").Query.Get("limit"); got != "50" {
		t.Errorf("default limit = %q", got)
	}
	f.fail("GET /api/open/audit", 403, "forbidden", "administrators only")
	contains(t, ta.wantExit(1, "audit"), "403", "administrators only")
}

func TestUsers(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/users", `{"data":[{"username":"admin","role":"admin","totp":true,"created_at":"2026-01-01T00:00:00Z"},
	  {"username":"view","role":"viewer","totp":false,"created_at":"2026-02-01T00:00:00Z"}],"total":2}`)
	f.ok("POST /api/open/users", nil)
	f.ok("DELETE /api/open/users", nil)
	ta := newTestApp(t).loggedIn(f)

	out := ta.mustRun("users", "list")
	contains(t, out, "USERNAME", "2FA", "admin", "yes", "view", "viewer")

	ta.env["HCWCTL_NEW_PASSWORD"] = "hunter2-password"
	contains(t, ta.mustRun("users", "add", "carol", "--role", "admin"), "User carol added (admin)")
	body := decodeBody(t, f.last("POST /api/open/users"))
	if !reflect.DeepEqual(body, map[string]any{"username": "carol", "password": "hunter2-password", "role": "admin"}) {
		t.Errorf("body = %v", body)
	}
	delete(ta.env, "HCWCTL_NEW_PASSWORD")
	ta.stdin = "hunter2-password\n"
	ta.mustRun("users", "add", "dave")
	if body := decodeBody(t, f.last("POST /api/open/users")); body["role"] != "viewer" || body["password"] != "hunter2-password" {
		t.Errorf("body = %v", body)
	}
	ta.stdin = ""
	contains(t, ta.wantExit(1, "users", "add", "eve", "--role", "root"), "invalid role")
	ta.wantExit(2, "users", "add")

	contains(t, ta.mustRun("users", "delete", "carol", "dave"), "Deleted user(s) carol,dave")
	if got := string(f.last("DELETE /api/open/users").Body); got != `{"usernames":["carol","dave"]}` {
		t.Errorf("delete body = %s", got)
	}
}

const backupJSON = `{"version":1,"exported_at":"2026-10-14T09:00:00Z","sites":[{"id":1,"name":"shop"},{"id":2,"name":"api"}],"certs":[{"id":1,"key":"K"}]}`

func TestBackup(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/backup", backupJSON)
	ta := newTestApp(t).loggedIn(f)
	out := ta.mustRun("backup")
	var b map[string]any
	if err := json.Unmarshal([]byte(out), &b); err != nil {
		t.Fatalf("backup is not JSON: %v\n%s", err, out)
	}
	if len(b["sites"].([]any)) != 2 || b["version"] != float64(1) {
		t.Errorf("backup = %v", b)
	}
	contains(t, ta.err.String(), "2 site(s) and 1 certificate(s)", "private keys")

	file := t.TempDir() + "/b.json"
	if out := ta.mustRun("backup", "--file", file); out != "" {
		t.Errorf("stdout with --file: %q", out)
	}
	st, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("backup mode %v", st.Mode().Perm())
	}
}

func TestRestore(t *testing.T) {
	f := newFake(t)
	f.ok("POST /api/open/restore", map[string]int{"sites": 2, "certs": 1})
	ta := newTestApp(t).loggedIn(f)
	file := writeFile(t, "backup.json", backupJSON)

	// Declined.
	ta.stdin = "no\n"
	contains(t, ta.wantExit(1, "restore", file), "REPLACES all sites", "2 site(s) and 1 certificate(s)", "aborted")
	if len(f.requests("POST /api/open/restore")) != 0 {
		t.Fatal("restore sent without confirmation")
	}
	// No answer at all.
	ta.stdin = ""
	ta.wantExit(1, "restore", file)

	ta.stdin = "yes\n"
	contains(t, ta.mustRun("restore", file), "Restored 2 site(s) and 1 certificate(s)")
	if got := string(f.last("POST /api/open/restore").Body); got != backupJSON {
		t.Errorf("restore body = %s", got)
	}

	ta.stdin = ""
	ta.mustRun("restore", "--yes", file)
	// The API envelope, as saved by curl, is accepted.
	ta.mustRun("restore", writeFile(t, "env.json", `{"data":`+backupJSON+`,"err":null,"msg":""}`), "-y")
	if got := string(f.last("POST /api/open/restore").Body); got != backupJSON {
		t.Errorf("envelope not unwrapped: %s", got)
	}
	contains(t, ta.wantExit(1, "restore", "--yes", writeFile(t, "x.json", `{"hello":1}`)), "not a HiTechCloud WAF backup")
	ta.wantExit(2, "restore", "-")
	ta.stdin = backupJSON
	ta.mustRun("restore", "-", "--yes")
	ta.wantExit(2, "restore")
	if n := len(f.requests("POST /api/open/restore")); n != 4 {
		t.Errorf("restore calls = %d, want 4", n)
	}
}

func TestAlertsTest(t *testing.T) {
	f := newFake(t)
	f.ok("POST /api/open/alerts/test", "sent")
	ta := newTestApp(t).loggedIn(f)
	contains(t, ta.mustRun("alerts", "test"), "Test alert sent")
	f.fail("POST /api/open/alerts/test", 409, "not_configured", "no alert channel configured")
	contains(t, ta.wantExit(1, "alerts", "test"), "409 not_configured: no alert channel configured")
	ta.wantExit(2, "alerts")
	ta.wantExit(2, "alerts", "send")
}

func TestVersion(t *testing.T) {
	ta := newTestApp(t)
	contains(t, ta.mustRun("version"), "hcwctl "+Version)

	f := newFake(t)
	f.ok("GET /api/open/info", map[string]any{"version": "0.4.0", "started_at": "2026-10-14T08:00:00Z", "sites": 3, "certs": 1})
	ta.loggedIn(f)
	out := ta.mustRun("version")
	contains(t, out, "hcwctl "+Version, "server 0.4.0 at "+f.srv.URL, "3 sites")
	var m map[string]map[string]any
	if err := json.Unmarshal([]byte(ta.mustRun("version", "-o", "json")), &m); err != nil || m["server"]["version"] != "0.4.0" {
		t.Errorf("json %v %v", m, err)
	}
	n := len(f.requests(""))
	ta.mustRun("version", "--client")
	if len(f.requests("")) != n {
		t.Error("--client contacted the server")
	}
	f.fail("GET /api/open/info", 500, "boom", "down")
	ta.wantExit(1, "version")
}

func TestUsageErrors(t *testing.T) {
	ta := newTestApp(t)
	contains(t, ta.wantExit(2), "Usage: hcwctl")
	contains(t, ta.wantExit(2, "frobnicate"), "unknown command")
	ta.wantExit(2, "sites", "list", "--bogus")
	ta.wantExit(2, "stats", "extra")
	ta.wantExit(2, "--nope")
	ta.wantExit(0, "help")
	contains(t, ta.out.String(), "sites", "certs", "events", "restore")
	ta.wantExit(0, "sites", "list", "-h")
	ta.wantExit(0, "users", "--help")
}
