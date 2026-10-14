package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

var pageBody = strings.Repeat("<p>Xin chào, đây là trang thử nghiệm nén gzip.</p>\n", 200)

// compressOrigin serves bodies whose type and framing depend on the path.
// Handlers that stream wait for release before their second part.
func compressOrigin(h *harness, release <-chan struct{}) *atomic.Int64 {
	var hits atomic.Int64
	h.origin.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		hd := w.Header()
		write := func(ct, body string) {
			hd.Set("Content-Type", ct)
			hd.Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = io.WriteString(w, body)
		}
		switch r.URL.Path {
		case "/page.html", "/static/app.js":
			hd.Set("ETag", `"v1"`)
			hd.Set("Accept-Ranges", "bytes")
			ct := "text/html; charset=utf-8"
			if strings.HasSuffix(r.URL.Path, ".js") {
				ct = "text/javascript; charset=utf-8"
			}
			write(ct, pageBody)
		case "/small.txt":
			write("text/plain", "tiny")
		case "/img.png":
			write("image/png", pageBody)
		case "/pre.js":
			hd.Set("Content-Encoding", "br")
			write("application/javascript", "\x1b\x03already-encoded")
		case "/stream.json", "/events":
			ct := "application/json"
			if r.URL.Path == "/events" {
				ct = "text/event-stream"
			}
			hd.Set("Content-Type", ct)
			_, _ = io.WriteString(w, "data: one\n\n")
			http.NewResponseController(w).Flush()
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			_, _ = io.WriteString(w, "data: two\n\n")
		default:
			http.NotFound(w, r)
		}
	})
	return &hits
}

func gunzip(t *testing.T, b string) string {
	t.Helper()
	zr, err := gzip.NewReader(strings.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func hasVary(resp *http.Response) bool {
	return strings.Contains(strings.ToLower(strings.Join(resp.Header.Values("Vary"), ",")), "accept-encoding")
}

var acceptGzip = map[string]string{"Accept-Encoding": "gzip, deflate, br"}

func TestGzipRoundTrip(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"z.vn"}, Compress: true})
	compressOrigin(h, nil)

	// Setting Accept-Encoding by hand turns off the client's transparent
	// decompression, so the raw encoding is visible.
	resp, body := h.fetch(t, "GET", "z.vn", "/page.html", acceptGzip)
	if resp.Header.Get("Content-Encoding") != "gzip" || !hasVary(resp) || resp.ContentLength != -1 || resp.Header.Get("Accept-Ranges") != "" {
		t.Fatalf("not compressed: %v", resp.Header)
	}
	if resp.Header.Get("ETag") != `W/"v1"` {
		t.Fatalf("etag = %q, want weak", resp.Header.Get("ETag"))
	}
	if len(body) >= len(pageBody) || gunzip(t, body) != pageBody {
		t.Fatalf("gzip round trip failed (%d bytes for %d)", len(body), len(pageBody))
	}

	// Bodies of unknown length are compressed too.
	release := make(chan struct{})
	close(release)
	compressOrigin(h, release)
	resp, body = h.fetch(t, "GET", "z.vn", "/stream.json", acceptGzip)
	if resp.Header.Get("Content-Encoding") != "gzip" || gunzip(t, body) != "data: one\n\ndata: two\n\n" {
		t.Fatalf("chunked json: %v", resp.Header)
	}

	untouched := []struct {
		name, method, path string
		hdr                map[string]string
		vary               bool
	}{
		{"identity client", "GET", "/page.html", map[string]string{"Accept-Encoding": "identity"}, true},
		{"gzip refused", "GET", "/page.html", map[string]string{"Accept-Encoding": "gzip;q=0, br"}, true},
		{"small body", "GET", "/small.txt", acceptGzip, true},
		{"image", "GET", "/img.png", acceptGzip, false},
		{"already encoded", "GET", "/pre.js", acceptGzip, false},
		{"HEAD", "HEAD", "/page.html", acceptGzip, true},
		{"404", "GET", "/nope", map[string]string{"Accept-Encoding": "gzip"}, true},
	}
	for _, c := range untouched {
		resp, body := h.fetch(t, c.method, "z.vn", c.path, c.hdr)
		ce := resp.Header.Get("Content-Encoding")
		if c.name == "already encoded" {
			if ce != "br" || body != "\x1b\x03already-encoded" {
				t.Errorf("%s: re-encoded: %q", c.name, ce)
			}
		} else if ce != "" {
			t.Errorf("%s: Content-Encoding %q", c.name, ce)
		}
		if hasVary(resp) != c.vary {
			t.Errorf("%s: Vary = %q", c.name, resp.Header.Values("Vary"))
		}
		if c.name == "identity client" && body != pageBody {
			t.Errorf("%s: body changed", c.name)
		}
		if c.name == "HEAD" && resp.ContentLength != int64(len(pageBody)) {
			t.Errorf("HEAD Content-Length = %d", resp.ContentLength)
		}
	}
}

func TestCompressOffByDefault(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"off.vn"}})
	compressOrigin(h, nil)
	resp, body := h.fetch(t, "GET", "off.vn", "/page.html", acceptGzip)
	if resp.Header.Get("Content-Encoding") != "" || hasVary(resp) || body != pageBody {
		t.Fatalf("compressed without compress: %v", resp.Header)
	}
}

// streamRead opens path and returns the response with a reader on the raw
// body, failing the test if the server takes too long.
func streamRead(t *testing.T, h *harness, host, path string) (*http.Response, *bufio.Reader) {
	t.Helper()
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d%s", h.port, path), nil)
	req.Host = host
	req.Header.Set("User-Agent", browser["User-Agent"])
	req.Header.Set("Accept-Encoding", "gzip")
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp, bufio.NewReader(resp.Body)
}

// Compressed responses keep streaming: each upstream flush is delivered
// before the upstream has finished.
func TestGzipKeepsStreaming(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"st.vn"}, Compress: true})
	release := make(chan struct{})
	compressOrigin(h, release)
	resp, br := streamRead(t, h, "st.vn", "/stream.json")
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("not compressed: %v", resp.Header)
	}
	zr, err := gzip.NewReader(br)
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, len("data: one\n\n"))
	if _, err := io.ReadFull(zr, first); err != nil || string(first) != "data: one\n\n" {
		t.Fatalf("first part before release: %q %v", first, err)
	}
	close(release)
	rest, err := io.ReadAll(zr)
	if err != nil || string(rest) != "data: two\n\n" {
		t.Fatalf("rest = %q %v", rest, err)
	}
}

func TestSSENotCompressed(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"sse.vn"}, Compress: true})
	release := make(chan struct{})
	compressOrigin(h, release)
	resp, br := streamRead(t, h, "sse.vn", "/events")
	if resp.Header.Get("Content-Encoding") != "" || hasVary(resp) {
		t.Fatalf("SSE compressed: %v", resp.Header)
	}
	line, err := br.ReadString('\n')
	if err != nil || line != "data: one\n" {
		t.Fatalf("first event before release: %q %v", line, err)
	}
	close(release)
	rest, _ := io.ReadAll(br)
	if string(rest) != "\ndata: two\n\n" {
		t.Fatalf("rest = %q", rest)
	}
}

// With compress on, WebSockets still upgrade and the access log records
// the bytes actually sent.
func TestCompressWithAccessLogAndWebSocket(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"ws.vn"}, Compress: true})
	ml := &memLog{}
	h.eng.opt.Access = ml
	compressOrigin(h, nil)
	_, body := h.fetch(t, "GET", "ws.vn", "/page.html", acceptGzip)
	if e := ml.next(t, 1); e.Status != 200 || e.Bytes != int64(len(body)) || e.Bytes >= int64(len(pageBody)) {
		t.Fatalf("access log = %+v, compressed body %d bytes", e, len(body))
	}

	h.origin.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		rw.Flush()
		line, _ := rw.ReadString('\n')
		fmt.Fprint(rw, "echo:"+line)
		rw.Flush()
	})
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(c, "GET /chat HTTP/1.1\r\nHost: ws.vn\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", err, resp)
	}
	fmt.Fprint(c, "xin chào\n")
	if got, _ := br.ReadString('\n'); strings.TrimSpace(got) != "echo:xin chào" {
		t.Fatalf("websocket echo = %q", got)
	}
}

// Cached objects are stored uncompressed with a gzip copy made once; each
// client gets the encoding it asked for.
func TestCacheServesBothEncodings(t *testing.T) {
	s := model.Site{ServerNames: []string{"cz.vn"}, Compress: true, Cache: model.CacheConfig{Enabled: true}}
	h := newHarness(t, nil, s)
	hits := compressOrigin(h, nil)

	resp, body := h.fetch(t, "GET", "cz.vn", "/static/app.js", acceptGzip)
	if resp.Header.Get("X-HCW-Cache") != "MISS" || resp.Header.Get("Content-Encoding") != "gzip" || gunzip(t, body) != pageBody {
		t.Fatalf("miss: %v", resp.Header)
	}
	resp, body = h.fetch(t, "GET", "cz.vn", "/static/app.js", acceptGzip)
	if resp.Header.Get("X-HCW-Cache") != "HIT" || resp.Header.Get("Content-Encoding") != "gzip" || !hasVary(resp) ||
		resp.ContentLength != int64(len(body)) || resp.Header.Get("ETag") != `W/"v1"` || gunzip(t, body) != pageBody {
		t.Fatalf("gzip hit: %v (%d bytes)", resp.Header, len(body))
	}
	resp, body = h.fetch(t, "GET", "cz.vn", "/static/app.js", map[string]string{"Accept-Encoding": "identity"})
	if resp.Header.Get("X-HCW-Cache") != "HIT" || resp.Header.Get("Content-Encoding") != "" || !hasVary(resp) || body != pageBody ||
		resp.Header.Get("ETag") != `"v1"` {
		t.Fatalf("identity hit: %v", resp.Header)
	}
	// Revalidating the gzip variant with its weak ETag.
	resp, _ = h.fetch(t, "GET", "cz.vn", "/static/app.js", map[string]string{"Accept-Encoding": "gzip", "If-None-Match": `W/"v1"`})
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("revalidation: %d", resp.StatusCode)
	}
	if hits.Load() != 1 {
		t.Fatalf("origin reached %d times", hits.Load())
	}
	ent, _ := h.eng.cache.get(cacheKey(1, &http.Request{Method: "GET", Host: "cz.vn", URL: mustURL("/static/app.js")}))
	if ent == nil || string(ent.body) != pageBody || ent.gzip == nil || !bytes.HasPrefix(ent.gzip, []byte{0x1f, 0x8b}) {
		t.Fatal("entry is not stored uncompressed with a gzip copy")
	}
}

func TestAcceptsGzip(t *testing.T) {
	cases := map[string]bool{
		"gzip": true, "gzip, deflate, br": true, "br": false, "": false, "identity": false,
		"gzip;q=0": false, "gzip; q=0.000": false, "GZIP;Q=0.8": true, "*": true, "*;q=0": false,
		"gzip;q=0, *": false, "br, *;q=0.5": true, "x-gzip": true,
	}
	for ae, want := range cases {
		r, _ := http.NewRequest("GET", "/", nil)
		if ae != "" {
			r.Header.Set("Accept-Encoding", ae)
		}
		if got := acceptsGzip(r); got != want {
			t.Errorf("%q: %v, want %v", ae, got, want)
		}
	}
}

func TestCompressibleType(t *testing.T) {
	cases := map[string]bool{
		"text/html; charset=utf-8": true, "text/css": true, "text/plain": true, "application/javascript": true,
		"application/json": true, "application/xml": true, "image/svg+xml": true,
		"text/event-stream": false, "image/png": false, "application/octet-stream": false, "": false, "video/mp4": false,
	}
	for ct, want := range cases {
		if got := compressibleType(ct); got != want {
			t.Errorf("%q: %v, want %v", ct, got, want)
		}
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
