package cli

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const twoSites = `{"data":[
 {"id":1,"name":"shop","server_names":["shop.example.com"],"ports":["80","443_ssl"],"upstreams":["http://10.0.0.5:8080"],
  "cert_id":2,"mode":"block","disabled_rules":[942100],"ip_deny":["1.2.3.4/32"],"future_field":{"x":1},"auth":{"enabled":true,"password_hash":"$2a$10$abc"}},
 {"id":7,"name":"api","server_names":["api.example.com"],"ports":["80"],"upstreams":["http://10.0.0.6"],"mode":"monitor","auto_tls":true}
],"total":2}`

func TestSitesListTableAndJSON(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/site", twoSites)
	ta := newTestApp(t).loggedIn(f)

	out := ta.mustRun("sites", "list")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("table:\n%s", out)
	}
	contains(t, lines[0], "ID", "NAME", "SERVER NAMES", "MODE")
	contains(t, lines[1], "1", "shop", "shop.example.com", "80,443_ssl", "block", "2")
	contains(t, lines[2], "7", "api", "monitor", "auto")
	if r := f.last("GET /api/open/site"); r.Header.Get("Content-Type") != "" || len(r.Body) != 0 {
		t.Errorf("GET with a body: %+v", r)
	}

	out = ta.mustRun("sites", "list", "-o", "json")
	var got []map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json output %q: %v", out, err)
	}
	if len(got) != 2 || got[0]["future_field"] == nil {
		t.Errorf("json output lost data: %v", got)
	}

	// -o before the command works too.
	if out := ta.mustRun("-o", "json", "sites", "list"); !strings.HasPrefix(out, "[") {
		t.Errorf("global -o ignored: %q", out)
	}
	ta.wantExit(2, "sites", "list", "-o", "yaml")
}

func TestSitesGet(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/site", twoSites)
	ta := newTestApp(t).loggedIn(f)
	out := ta.mustRun("sites", "get", "1")
	contains(t, out, "server_names", "shop.example.com", "disabled_rules", "942100", "ip_deny", "1.2.3.4/32")
	out = ta.mustRun("sites", "get", "7", "-o", "json")
	contains(t, out, `"name": "api"`)
	contains(t, ta.wantExit(1, "sites", "get", "99"), "site 99 not found")
	ta.wantExit(2, "sites", "get")
	contains(t, ta.wantExit(1, "sites", "get", "abc"), "invalid site ID")
}

func TestSitesCreateUpdateDelete(t *testing.T) {
	f := newFake(t)
	f.handle("POST /api/open/site", func(w http.ResponseWriter, r *http.Request) {
		var s map[string]any
		_ = json.NewDecoder(r.Body).Decode(&s)
		s["id"], s["mode"] = 3, "block"
		envelope(w, 200, s, "", "")
	})
	f.handle("PUT /api/open/site", func(w http.ResponseWriter, r *http.Request) {
		var s map[string]any
		_ = json.NewDecoder(r.Body).Decode(&s)
		envelope(w, 200, s, "", "")
	})
	f.ok("DELETE /api/open/site", nil)
	ta := newTestApp(t).loggedIn(f)

	file := writeFile(t, "site.json", `{"id": 99, "name":"blog","server_names":["blog.example.com"],"upstreams":["http://10.0.0.9"],"custom":true}`)
	out := ta.mustRun("sites", "create", "-f", file)
	contains(t, out, "Site 3 (blog) created", "blog.example.com")
	r := f.last("POST /api/open/site")
	if r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("content type %q", r.Header.Get("Content-Type"))
	}
	body := decodeBody(t, r)
	if _, ok := body["id"]; ok {
		t.Error("create sent the file's id")
	}
	if body["custom"] != true || body["name"] != "blog" {
		t.Errorf("create body = %v", body)
	}

	// Create from stdin.
	ta.stdin = `{"server_names":["x.example.com"],"upstreams":["http://10.0.0.1"]}`
	ta.mustRun("sites", "create", "-f", "-")
	if decodeBody(t, f.last("POST /api/open/site"))["server_names"] == nil {
		t.Error("stdin site not sent")
	}
	ta.stdin = ""

	ta.wantExit(2, "sites", "create")
	contains(t, ta.wantExit(1, "sites", "create", "-f", writeFile(t, "bad.json", "[1,2]")), "bad.json")

	// Update needs an id, from the file or the argument.
	noID := writeFile(t, "noid.json", `{"name":"blog","server_names":["blog.example.com"],"upstreams":["http://10.0.0.9"]}`)
	contains(t, ta.wantExit(1, "sites", "update", "-f", noID), "needs the site ID")
	ta.mustRun("sites", "update", "3", "-f", noID)
	if got := decodeBody(t, f.last("PUT /api/open/site"))["id"]; got != float64(3) {
		t.Errorf("update id = %v", got)
	}
	out = ta.mustRun("sites", "update", "-f", file, "-o", "json")
	contains(t, out, `"id": 99`)

	out = ta.mustRun("sites", "delete", "3", "4")
	contains(t, out, "Deleted site(s) 3,4")
	if got := string(f.last("DELETE /api/open/site").Body); got != `{"ids":[3,4]}` {
		t.Errorf("delete body = %s", got)
	}
	ta.wantExit(2, "sites", "delete")
	ta.wantExit(2, "sites", "frobnicate")
	ta.wantExit(2, "sites")
}

// putSite records the site sent by PUT and echoes it.
func putSite(f *fakeAPI) {
	f.handle("PUT /api/open/site", func(w http.ResponseWriter, r *http.Request) {
		var s map[string]any
		_ = json.NewDecoder(r.Body).Decode(&s)
		envelope(w, 200, s, "", "")
	})
}

func TestSitesSetMode(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/site", twoSites)
	putSite(f)
	ta := newTestApp(t).loggedIn(f)

	out := ta.mustRun("sites", "set-mode", "1", "monitor")
	contains(t, out, "Site 1: mode block -> monitor")
	body := decodeBody(t, f.last("PUT /api/open/site"))
	if body["mode"] != "monitor" || body["id"] != float64(1) {
		t.Errorf("PUT body = %v", body)
	}
	// Unknown and secret fields survive the round trip untouched.
	if !reflect.DeepEqual(body["future_field"], map[string]any{"x": float64(1)}) {
		t.Errorf("unknown field lost: %v", body["future_field"])
	}
	if body["auth"].(map[string]any)["password_hash"] != "$2a$10$abc" {
		t.Errorf("auth hash lost: %v", body["auth"])
	}

	// No change: no PUT.
	n := len(f.requests("PUT /api/open/site"))
	contains(t, ta.mustRun("sites", "set-mode", "1", "block"), "no change")
	if len(f.requests("PUT /api/open/site")) != n {
		t.Error("PUT sent although nothing changed")
	}
	contains(t, ta.wantExit(1, "sites", "set-mode", "1", "panic"), "invalid mode")
	ta.wantExit(2, "sites", "set-mode", "1")
	contains(t, ta.wantExit(1, "sites", "set-mode", "42", "off"), "site 42 not found")
	if len(f.requests("PUT /api/open/site")) != n {
		t.Error("PUT sent for an invalid request")
	}
}

func TestSitesDenyIP(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/site", twoSites)
	putSite(f)
	ta := newTestApp(t).loggedIn(f)

	out := ta.mustRun("sites", "deny-ip", "1", "5.6.7.8", "10.1.2.3/8", "1.2.3.4", "2001:db8::1")
	contains(t, out, "denied 5.6.7.8/32, 10.0.0.0/8, 2001:db8::1/128")
	got := decodeBody(t, f.last("PUT /api/open/site"))["ip_deny"]
	want := []any{"1.2.3.4/32", "5.6.7.8/32", "10.0.0.0/8", "2001:db8::1/128"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ip_deny = %v, want %v", got, want)
	}
	contains(t, ta.wantExit(1, "sites", "deny-ip", "1", "999.1.1.1"), "invalid IP/CIDR")
	contains(t, ta.mustRun("sites", "deny-ip", "1", "1.2.3.4/32"), "no change")
	// A site without ip_deny.
	ta.mustRun("sites", "deny-ip", "7", "9.9.9.9")
	if got := decodeBody(t, f.last("PUT /api/open/site"))["ip_deny"]; !reflect.DeepEqual(got, []any{"9.9.9.9/32"}) {
		t.Errorf("ip_deny = %v", got)
	}
}

func TestSitesRules(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/site", twoSites)
	putSite(f)
	ta := newTestApp(t).loggedIn(f)

	contains(t, ta.mustRun("sites", "disable-rule", "1", "941100", "942100"), "disabled rule(s) 941100")
	if got := decodeBody(t, f.last("PUT /api/open/site"))["disabled_rules"]; !reflect.DeepEqual(got, []any{float64(942100), float64(941100)}) {
		t.Errorf("disabled_rules = %v", got)
	}
	contains(t, ta.mustRun("sites", "allow-rule", "1", "942100"), "re-enabled rule(s) 942100")
	if got := decodeBody(t, f.last("PUT /api/open/site"))["disabled_rules"]; !reflect.DeepEqual(got, []any{}) {
		t.Errorf("disabled_rules = %v", got)
	}
	contains(t, ta.mustRun("sites", "allow-rule", "7", "942100"), "no change")
	contains(t, ta.wantExit(1, "sites", "disable-rule", "1", "x"), "invalid rule ID")

	// Server-side validation errors are reported with exit 1.
	f.fail("PUT /api/open/site", 400, "invalid", "disabled rule 12 is not a CRS rule id")
	contains(t, ta.wantExit(1, "sites", "disable-rule", "1", "12"), "API error 400 invalid: disabled rule 12 is not a CRS rule id")
}

func TestUnauthorizedHint(t *testing.T) {
	f := newFake(t)
	ta := newTestApp(t).loggedIn(f)
	ta.env["HCWCTL_TOKEN"] = "expired"
	contains(t, ta.wantExit(1, "sites", "list"), "401", "unauthorized", "hcwctl login")
}

func TestTerminalEscapesCleaned(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/site", `{"data":[{"id":1,"name":"evil\u001b[2J\u0007name","server_names":["a"],"mode":"block"}]}`)
	ta := newTestApp(t).loggedIn(f)
	out := ta.mustRun("sites", "list")
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Errorf("control characters printed: %q", out)
	}
	contains(t, out, "evil?[2J?name")
}
