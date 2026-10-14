package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

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

// The encoders below write the whole response into one buffer allocated at
// its final size: the payload is XORed and base64-encoded in small chunks
// straight into it, with no intermediate copies of the body.

const (
	dynKeyLen   = 16
	dynIdentRnd = 9 // random letters of an identifier, after "_"
	dynIdents   = 5 // identifiers per loader: 1 for the wrapper + 4 for the decoder
	// dynRandLen is the randomness of one response, read at once: the key,
	// then the identifiers in the order they are used.
	dynRandLen = dynKeyLen + dynIdents*dynIdentRnd
)

type dynIdent [1 + dynIdentRnd]byte

// dynamicRand returns fresh random bytes for one response.
func dynamicRand() []byte {
	b := make([]byte, dynRandLen)
	_, _ = rand.Read(b)
	return b
}

// dynamicIdents turns rnd (after the key) into JavaScript identifiers, so
// the loader itself does not have a stable fingerprint either.
func dynamicIdents(rnd []byte) (ids [dynIdents]dynIdent) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	rnd = rnd[dynKeyLen:]
	for n := range ids {
		ids[n][0] = '_'
		for j, c := range rnd[n*dynIdentRnd : (n+1)*dynIdentRnd] {
			ids[n][1+j] = letters[int(c)%len(letters)]
		}
	}
	return ids
}

// appendPayload appends base64(b XOR keystream).
func appendPayload(dst, b, key []byte) []byte {
	n := base64.StdEncoding.EncodedLen(len(b))
	dst = slices.Grow(dst, n)
	out := dst[len(dst) : len(dst)+n]
	// A multiple of 3 (only the last chunk is padded) and of 16 (every
	// chunk starts at a keystream block).
	var chunk [3 << 10]byte
	o := 0
	for i := 0; i < len(b); i += len(chunk) {
		c := chunk[:min(len(chunk), len(b)-i)]
		src := b[i : i+len(c)]
		for j := 0; j < len(c); j += 16 {
			// dynamicMask, one 16-byte block at a time
			blk := byte((i + j) >> 4)
			s, d := src[j:min(j+16, len(c))], c[j:min(j+16, len(c))]
			for t := range d {
				d[t] = s[t] ^ key[t] ^ blk
			}
		}
		base64.StdEncoding.Encode(out[o:], c)
		o += base64.StdEncoding.EncodedLen(len(c))
	}
	return dst[:len(dst)+n]
}

// appendDecoder appends an expression that evaluates to the decoded UTF-8
// text. ids are its four identifiers. The base64 alphabet needs no escaping
// inside a JavaScript string.
func appendDecoder(dst, b, key []byte, ids []dynIdent) []byte {
	d, k, u, i := ids[0][:], ids[1][:], ids[2][:], ids[3][:]
	dst = append(dst, "(function(){var "...)
	dst = append(dst, d...)
	dst = append(dst, `=atob("`...)
	dst = appendPayload(dst, b, key)
	dst = append(dst, `"),`...)
	dst = append(dst, k...)
	dst = append(dst, "=["...)
	for n, c := range key {
		if n > 0 {
			dst = append(dst, ',')
		}
		dst = strconv.AppendInt(dst, int64(c), 10)
	}
	dst = append(dst, "],"...)
	dst = append(dst, u...)
	dst = append(dst, "=new Uint8Array("...)
	dst = append(dst, d...)
	dst = append(dst, ".length);for(var "...)
	dst = append(dst, i...)
	dst = append(dst, "=0;"...)
	dst = append(dst, i...)
	dst = append(dst, '<')
	dst = append(dst, d...)
	dst = append(dst, ".length;"...)
	dst = append(dst, i...)
	dst = append(dst, "++)"...)
	dst = append(dst, u...)
	dst = append(dst, '[')
	dst = append(dst, i...)
	dst = append(dst, "]="...)
	dst = append(dst, d...)
	dst = append(dst, ".charCodeAt("...)
	dst = append(dst, i...)
	dst = append(dst, ")^"...)
	dst = append(dst, k...)
	dst = append(dst, '[')
	dst = append(dst, i...)
	dst = append(dst, "&15]^(("...)
	dst = append(dst, i...)
	dst = append(dst, `>>4)&255);return new TextDecoder("utf-8").decode(`...)
	dst = append(dst, u...)
	return append(dst, ")})()"...)
}

// dynamicBufLen is an upper bound of a loader's size around a payload of
// n bytes: the base64 text plus the fixed JavaScript (< 1 KB).
func dynamicBufLen(n int) int { return base64.StdEncoding.EncodedLen(n) + 1024 }

const (
	htmlHead = "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noarchive\"></head><body>" +
		"<noscript>Vui lòng bật JavaScript để xem trang này. / Please enable JavaScript.</noscript><script>"
	htmlTail = "</script></body></html>"
)

func protectHTML(html []byte) []byte { return protectHTMLRand(html, dynamicRand()) }

// protectHTMLRand builds the loader page with the randomness rnd (key and
// identifiers, see dynRandLen).
func protectHTMLRand(html, rnd []byte) []byte {
	key, ids := rnd[:dynKeyLen], dynamicIdents(rnd)
	fn := ids[0][:]
	b := make([]byte, 0, dynamicBufLen(len(html)))
	b = append(b, htmlHead...)
	// Replace the document from a fresh task once the loader has finished
	// parsing: document.open() then swaps the whole document (head included)
	// and the original page's scripts, external ones too, run normally.
	// Calling it from within DOMContentLoaded truncates the written document
	// at its first external script in Chromium, hence the setTimeout.
	b = append(b, "(function(){function "...)
	b = append(b, fn...)
	b = append(b, "(){var h="...)
	b = appendDecoder(b, html, key, ids[1:])
	b = append(b, ";document.open();document.write(h);document.close();}function g(){setTimeout("...)
	b = append(b, fn...)
	b = append(b, ",0)}if(document.readyState===\"loading\"){document.addEventListener(\"DOMContentLoaded\",g)}else{g()}})();"...)
	return append(b, htmlTail...)
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
	return protectJSRand(js, dynamicRand()), true
}

func protectJSRand(js, rnd []byte) []byte {
	key, ids := rnd[:dynKeyLen], dynamicIdents(rnd)
	s := ids[0][:]
	b := make([]byte, 0, dynamicBufLen(len(js)))
	b = append(b, "(function(){var "...)
	b = append(b, s...)
	b = append(b, "=document.createElement(\"script\");"...)
	b = append(b, s...)
	b = append(b, ".text="...)
	b = appendDecoder(b, js, key, ids[1:])
	b = append(b, ";(document.head||document.documentElement).appendChild("...)
	b = append(b, s...)
	b = append(b, ");"...)
	b = append(b, s...)
	b = append(b, ".parentNode.removeChild("...)
	b = append(b, s...)
	return append(b, ");})();"...)
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

// dynBufs recycles the buffers upstream bodies are read into: the body is
// only needed until it has been encoded.
var dynBufs sync.Pool // *[]byte

const dynBufKeep = 1 << 20 // larger buffers are left to the GC

// readDynamicBody reads at most limit bytes of r into a pooled buffer sized
// from Content-Length when it is known.
func readDynamicBody(r io.Reader, size int64, limit int) (*[]byte, error) {
	bp, _ := dynBufs.Get().(*[]byte)
	if bp == nil {
		bp = new([]byte)
	}
	buf := (*bp)[:0]
	if want := int(min(max(size, 32<<10), int64(limit))) + 1; cap(buf) < want {
		buf = make([]byte, 0, want) // +1: see EOF without growing
	}
	for len(buf) < limit {
		if len(buf) == cap(buf) {
			buf = slices.Grow(buf, min(len(buf), limit-len(buf)))
		}
		n, err := r.Read(buf[len(buf):min(cap(buf), limit)])
		buf = buf[:len(buf)+n]
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	*bp = buf
	return bp, nil
}

func putDynamicBuf(bp *[]byte) {
	if cap(*bp) <= dynBufKeep {
		*bp = (*bp)[:0]
		dynBufs.Put(bp)
	}
}

// applyDynamic rewrites resp in place when dynamic protection applies.
func applyDynamic(d model.DynamicProtection, resp *http.Response) error {
	kind := dynamicKind(d, resp)
	if kind == "" {
		return nil
	}
	bp, err := readDynamicBody(resp.Body, resp.ContentLength, maxDynamicBody+1)
	if err != nil {
		return err
	}
	body := *bp
	if len(body) > maxDynamicBody {
		// Too large: pass through untouched (the buffer goes with it).
		resp.Body = multiCloser{io.MultiReader(bytes.NewReader(body), resp.Body), resp.Body}
		return nil
	}
	resp.Body.Close()
	var out []byte
	switch kind {
	case "html":
		out = protectHTML(body)
		putDynamicBuf(bp)
	case "js":
		var ok bool
		if out, ok = protectJS(body); ok {
			putDynamicBuf(bp)
		} else {
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
