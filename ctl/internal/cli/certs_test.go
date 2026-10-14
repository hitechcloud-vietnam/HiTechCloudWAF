package cli

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const privateKey = "-----BEGIN PRIVATE KEY-----\nTOP-SECRET-KEY\n-----END PRIVATE KEY-----\n"

func TestCertsList(t *testing.T) {
	f := newFake(t)
	f.ok("GET /api/open/cert", `{"data":[
	 {"id":2,"domains":["shop.example.com","www.shop.example.com"],"crt":"-----BEGIN CERTIFICATE-----","key":"`+strings.ReplaceAll(privateKey, "\n", `\n`)+`",
	  "issuer":"R11","not_after":"2099-01-01T00:00:00Z"},
	 {"id":3,"domains":["old.example.com"],"issuer":"Old CA","not_after":"2001-01-01T00:00:00Z"}],"total":2}`)
	ta := newTestApp(t).loggedIn(f)

	out := ta.mustRun("certs", "list")
	contains(t, out, "DOMAINS", "shop.example.com,www.shop.example.com", "R11", "2099-01-01", "EXPIRED")
	if strings.Contains(out, "TOP-SECRET-KEY") {
		t.Error("private key printed")
	}
	out = ta.mustRun("certs", "list", "-o", "json")
	if strings.Contains(out, "TOP-SECRET-KEY") {
		t.Error("private key printed in JSON")
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got[0]["key"] != "<redacted>" || got[0]["issuer"] != "R11" || got[1]["key"] != nil {
		t.Errorf("json = %v", got)
	}
}

func TestCertsAddDelete(t *testing.T) {
	f := newFake(t)
	f.handle("POST /api/open/cert", func(w http.ResponseWriter, r *http.Request) {
		var c map[string]any
		_ = json.NewDecoder(r.Body).Decode(&c)
		c["id"], c["issuer"], c["not_after"] = 5, "Test CA", "2030-05-01T00:00:00Z"
		if c["domains"] == nil {
			c["domains"] = []string{"from-cert.example.com"}
		}
		envelope(w, 200, c, "", "")
	})
	f.ok("DELETE /api/open/cert", nil)
	ta := newTestApp(t).loggedIn(f)
	crt := writeFile(t, "tls.crt", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	key := writeFile(t, "tls.key", privateKey)

	out := ta.mustRun("certs", "add", "--crt", crt, "--key", key)
	contains(t, out, "Certificate 5 added", "from-cert.example.com", "Test CA")
	body := decodeBody(t, f.last("POST /api/open/cert"))
	if body["crt"] != "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n" || body["key"] != privateKey {
		t.Errorf("body = %v", body)
	}
	if _, ok := body["domains"]; ok {
		t.Error("domains sent although not given")
	}
	out = ta.mustRun("certs", "add", "--crt", crt, "--key", key, "--domains", "a.example.com, b.example.com", "-o", "json")
	if strings.Contains(out, "TOP-SECRET-KEY") {
		t.Error("key echoed")
	}
	if got := decodeBody(t, f.last("POST /api/open/cert"))["domains"]; !reflect.DeepEqual(got, []any{"a.example.com", "b.example.com"}) {
		t.Errorf("domains = %v", got)
	}
	ta.wantExit(2, "certs", "add", "--crt", crt)
	ta.wantExit(1, "certs", "add", "--crt", crt, "--key", "/nonexistent/key")

	contains(t, ta.mustRun("certs", "delete", "5"), "Deleted certificate(s) 5")
	if got := string(f.last("DELETE /api/open/cert").Body); got != `{"ids":[5]}` {
		t.Errorf("delete body %s", got)
	}
	f.fail("DELETE /api/open/cert", 400, "invalid", "certificate 5 is used by site 1")
	contains(t, ta.wantExit(1, "certs", "delete", "5"), "used by site 1")
}
