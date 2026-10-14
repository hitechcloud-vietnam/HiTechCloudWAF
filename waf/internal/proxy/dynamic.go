package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

// Dynamic protection replaces HTML pages and JavaScript files with a small
// loader that carries the original content encoded with a key that is new
// for every response. Browsers decode and run it; scrapers that do not run
// JavaScript only ever see a random blob that differs on each request.
//
// This is obfuscation, not encryption: the key travels with the page. Its
// purpose is to raise the cost of scraping and of static analysis of the
// site, as in SafeLine's dynamic protection.

const maxDynamicBody = 4 << 20

// dynamicMask is the keystream; the JavaScript decoders mirror it exactly.
func dynamicMask(key []byte, i int) byte { return key[i&15] ^ byte(i>>4) }

func dynamicEncode(b []byte) (payload string, key []byte) {
	key = make([]byte, 16)
	_, _ = rand.Read(key)
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ dynamicMask(key, i)
	}
	return base64.StdEncoding.EncodeToString(out), key
}

// dynamicDecode is the Go twin of the JavaScript decoder (used by tests).
func dynamicDecode(payload string, key []byte) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}
	for i := range b {
		b[i] ^= dynamicMask(key, i)
	}
	return b, nil
}

// ident returns a fresh random JavaScript identifier, so the loader itself
// does not have a stable fingerprint either.
func ident() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	out := []byte{'_'}
	for _, c := range b {
		out = append(out, letters[int(c)%len(letters)])
	}
	return string(out)
}

func keyLiteral(key []byte) string {
	parts := make([]string, len(key))
	for i, k := range key {
		parts[i] = strconv.Itoa(int(k))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// decoderJS returns an expression that evaluates to the decoded UTF-8 text.
func decoderJS(payload string, key []byte) string {
	p, _ := json.Marshal(payload)
	d, k, u, i := ident(), ident(), ident(), ident()
	return "(function(){var " + d + "=atob(" + string(p) + ")," + k + "=" + keyLiteral(key) +
		"," + u + "=new Uint8Array(" + d + ".length);for(var " + i + "=0;" + i + "<" + d + ".length;" + i + "++)" +
		u + "[" + i + "]=" + d + ".charCodeAt(" + i + ")^" + k + "[" + i + "&15]^((" + i + ">>4)&255);" +
		"return new TextDecoder(\"utf-8\").decode(" + u + ")})()"
}

func protectHTML(html []byte) []byte {
	payload, key := dynamicEncode(html)
	fn := ident()
	var b bytes.Buffer
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noarchive\"></head><body>")
	b.WriteString("<noscript>Vui lòng bật JavaScript để xem trang này. / Please enable JavaScript.</noscript><script>")
	// Replace the document from a fresh task once the loader has finished
	// parsing: document.open() then swaps the whole document (head included)
	// and the original page's scripts, external ones too, run normally.
	// Calling it from within DOMContentLoaded truncates the written document
	// at its first external script in Chromium, hence the setTimeout.
	b.WriteString("(function(){function " + fn + "(){var h=" + decoderJS(payload, key) + ";document.open();document.write(h);document.close();}")
	b.WriteString("function g(){setTimeout(" + fn + ",0)}")
	b.WriteString("if(document.readyState===\"loading\"){document.addEventListener(\"DOMContentLoaded\",g)}else{g()}})();")
	b.WriteString("</script></body></html>")
	return b.Bytes()
}

// ES modules are loaded differently (deferred, own scope); leave them alone.
var jsModuleRe = regexp.MustCompile(`(?m)^\s*(?:import\s*[\w{*'"]|export\s)`)

// protectJS wraps a classic script. The decoded source is run through a new
// inline <script> element: it executes synchronously, in the global scope,
// with the same strict/sloppy mode and top-level let/const/class semantics
// as the original file (indirect eval would scope those to the eval).
func protectJS(js []byte) ([]byte, bool) {
	if jsModuleRe.Match(js) {
		return nil, false
	}
	payload, key := dynamicEncode(js)
	s := ident()
	return []byte("(function(){var " + s + "=document.createElement(\"script\");" + s + ".text=" + decoderJS(payload, key) +
		";(document.head||document.documentElement).appendChild(" + s + ");" + s + ".parentNode.removeChild(" + s + ");})();"), true
}

func pathMatches(path string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// dynamicKind tells which transformation applies to resp, or "".
func dynamicKind(d model.DynamicProtection, resp *http.Response) string {
	if resp.Request == nil || resp.Request.Method != http.MethodGet || resp.StatusCode != http.StatusOK {
		return ""
	}
	if !pathMatches(resp.Request.URL.Path, d.Paths) {
		return ""
	}
	// Pages with their own CSP would refuse the inline loader or eval.
	if resp.Header.Get("Content-Security-Policy") != "" {
		return ""
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
		return ""
	}
	if resp.ContentLength > maxDynamicBody {
		return ""
	}
	mt, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return ""
	}
	if cs := strings.ToLower(params["charset"]); cs != "" && cs != "utf-8" && cs != "utf8" {
		return ""
	}
	switch mt {
	case "text/html":
		if d.HTML {
			return "html"
		}
	case "application/javascript", "text/javascript", "application/x-javascript", "application/ecmascript":
		if d.JS {
			return "js"
		}
	}
	return ""
}

type multiCloser struct {
	io.Reader
	io.Closer
}

// applyDynamic rewrites resp in place when dynamic protection applies.
func applyDynamic(d model.DynamicProtection, resp *http.Response) error {
	kind := dynamicKind(d, resp)
	if kind == "" {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDynamicBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxDynamicBody {
		// Too large: pass through untouched.
		resp.Body = multiCloser{io.MultiReader(bytes.NewReader(body), resp.Body), resp.Body}
		return nil
	}
	resp.Body.Close()
	var out []byte
	switch kind {
	case "html":
		out = protectHTML(body)
	case "js":
		var ok bool
		if out, ok = protectJS(body); !ok {
			out = body
			kind = ""
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	if kind != "" {
		resp.Header.Del("ETag")
		resp.Header.Del("Last-Modified")
		resp.Header.Set("Cache-Control", "no-store, private")
		resp.Header.Set("X-HCW-Protected", kind)
	}
	return nil
}
