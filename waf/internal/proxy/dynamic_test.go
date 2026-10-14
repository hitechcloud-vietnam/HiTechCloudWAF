package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

const pageHTML = `<!doctype html><html lang="vi"><head><title>Cửa hàng</title></head><body><h1 id="t">Giá sản phẩm: 199.000đ</h1><script>document.getElementById("t").dataset.ran="1"</script></body></html>`

var (
	payloadRe = regexp.MustCompile(`atob\("([A-Za-z0-9+/=]+)"\),_[A-Za-z]+=\[([0-9,]+)\]`)
)

func extract(t *testing.T, out string) string {
	t.Helper()
	m := payloadRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no payload in %q", out[:min(200, len(out))])
	}
	var key []byte
	for _, p := range strings.Split(m[2], ",") {
		var n int
		fmt.Sscan(p, &n)
		key = append(key, byte(n))
	}
	b, err := dynamicDecode(m[1], key)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDynamicEncodingRoundTrip(t *testing.T) {
	a, b := string(protectHTML([]byte(pageHTML))), string(protectHTML([]byte(pageHTML)))
	if a == b {
		t.Fatal("two responses are identical")
	}
	if strings.Contains(a, "199.000") || strings.Contains(a, "Cửa hàng") {
		t.Fatal("original content visible in protected page")
	}
	if extract(t, a) != pageHTML || extract(t, b) != pageHTML {
		t.Fatal("round trip changed the page")
	}
}

func TestProtectJSSkipsModules(t *testing.T) {
	for _, src := range []string{
		"import {a} from './a.js'; a()",
		"export const x = 1",
	} {
		if _, ok := protectJS([]byte(src)); ok {
			t.Errorf("protected %q", src)
		}
	}
	if _, ok := protectJS([]byte("var important = 1; // import later\nfunction f(){ 'use strict'; }")); !ok {
		t.Error("classic script not protected")
	}
}

func TestDynamicKind(t *testing.T) {
	d := model.DynamicProtection{HTML: true, JS: true, Paths: []string{"/shop"}}
	mk := func(path, ct string, hdr map[string]string) *http.Response {
		req, _ := http.NewRequest("GET", "http://x"+path, nil)
		r := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {ct}}, Request: req, ContentLength: -1}
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	cases := []struct {
		resp *http.Response
		want string
	}{
		{mk("/shop/a", "text/html; charset=utf-8", nil), "html"},
		{mk("/shop/app.js", "application/javascript", nil), "js"},
		{mk("/blog", "text/html", nil), ""},
		{mk("/shop", "text/html", map[string]string{"Content-Security-Policy": "script-src 'self'"}), ""},
		{mk("/shop", "text/html", map[string]string{"Content-Encoding": "br"}), ""},
		{mk("/shop", "text/html; charset=windows-1258", nil), ""},
		{mk("/shop", "application/json", nil), ""},
	}
	for i, c := range cases {
		if got := dynamicKind(d, c.resp); got != c.want {
			t.Errorf("case %d: %q, want %q", i, got, c.want)
		}
	}
}

func TestDynamicThroughProxyWithGzipUpstream(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"d.vn"}, Mode: model.ModeOff, Dynamic: model.DynamicProtection{HTML: true, JS: true}})
	// Replace the origin with one that compresses when asked.
	gz := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ct := pageHTML, "text/html; charset=utf-8"
		if strings.HasSuffix(r.URL.Path, ".js") {
			body, ct = "var greeting = 'Xin chào';", "application/javascript"
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("ETag", `"v1"`)
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = io.WriteString(zw, body)
			zw.Close()
			return
		}
		_, _ = io.WriteString(w, body)
	})
	h.origin.Config.Handler = gz

	resp, body := h.do(t, "GET", "d.vn", "/", nil, nil, map[string]string{"Accept-Encoding": "gzip"})
	if resp.Header.Get("X-HCW-Protected") != "html" || resp.Header.Get("ETag") != "" || strings.Contains(body, "199.000") {
		t.Fatalf("html not protected: %v %q", resp.Header, body[:min(100, len(body))])
	}
	if extract(t, body) != pageHTML {
		t.Fatal("html payload does not decode to the original")
	}
	resp, body = h.do(t, "GET", "d.vn", "/app.js", nil, nil, nil)
	if resp.Header.Get("X-HCW-Protected") != "js" || strings.Contains(body, "Xin chào") {
		t.Fatalf("js not protected: %q", body)
	}
}

// The protected script must behave exactly like the original in a real
// JavaScript engine: globals stay global and UTF-8 text survives.
func TestProtectedJSRunsInNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	src := "'use strict'; var greeting = 'Xin chào thế giới'; function hello(){ return greeting + '!'; } let counter = 41; counter++; class Strict {}"
	out, ok := protectJS([]byte(src))
	if !ok {
		t.Fatal("not protected")
	}
	if bytes.Contains(out, []byte("greeting")) {
		t.Fatal("source visible")
	}
	script := filepath.Join(t.TempDir(), "t.js")
	// Run as a classic script in a fresh global context, like a browser.
	// A minimal DOM whose appendChild runs inline scripts in the global
	// context, as browsers do.
	runner := `const vm=require('vm');const ctx=vm.createContext({atob,TextDecoder,Uint8Array});` +
		`const el={text:'',parentNode:{removeChild(){}}};` +
		`ctx.document={createElement:()=>el,head:{appendChild(n){vm.runInContext(n.text,ctx)}}};` +
		`vm.runInContext(require('fs').readFileSync(process.argv[1],'utf8'),ctx);` +
		`console.log(vm.runInContext('hello()+"|"+counter+"|"+typeof Strict',ctx));`
	if err := os.WriteFile(script, out, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := exec.Command(node, "-e", runner, script).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, res)
	}
	if got := strings.TrimSpace(string(res)); got != "Xin chào thế giới!|42|function" {
		t.Fatalf("protected script returned %q", got)
	}
}
