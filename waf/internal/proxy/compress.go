package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// On-the-fly gzip for sites with compress on. The decision is taken from
// the response headers alone, when the status is written, so nothing is
// buffered: responses keep streaming and every Flush from the reverse
// proxy reaches the client as a gzip sync flush.

// minCompressSize is the smallest declared body worth compressing; below
// it the gzip framing costs about as much as it saves. Bodies of unknown
// length (chunked, streamed) are compressed, since waiting to learn their
// size would hold back streamed data.
const minCompressSize = 1024

// gzipLevel trades a little ratio for much less CPU than the default
// level, which matters when every response passes through the node.
const gzipLevel = 5

var gzipPool = sync.Pool{New: func() any {
	zw, _ := gzip.NewWriterLevel(io.Discard, gzipLevel)
	return zw
}}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzipPool.Get().(*gzip.Writer)
	zw.Reset(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	gzipPool.Put(zw)
	return buf.Bytes()
}

// compressibleType reports whether a Content-Type benefits from gzip.
// Server-sent events are left alone: EventSource clients and intermediaries
// expect them unencoded, event by event.
func compressibleType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil || mt == "text/event-stream" {
		return false
	}
	if strings.HasPrefix(mt, "text/") {
		return true
	}
	switch mt {
	case "application/javascript", "application/x-javascript", "application/json", "application/xml", "image/svg+xml":
		return true
	}
	return false
}

// acceptsGzip parses Accept-Encoding, honouring q=0 refusals and "*".
func acceptsGzip(r *http.Request) bool {
	gz, star := -1, -1 // -1 not mentioned, 0 refused, 1 accepted
	for _, v := range r.Header.Values("Accept-Encoding") {
		for _, part := range strings.Split(v, ",") {
			name, params, _ := strings.Cut(part, ";")
			ok := 1
			if qZero(params) {
				ok = 0
			}
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "gzip", "x-gzip":
				gz = ok
			case "*":
				star = ok
			}
		}
	}
	if gz >= 0 {
		return gz == 1
	}
	return star == 1
}

func qZero(params string) bool {
	for _, p := range strings.Split(params, ";") {
		k, v, _ := strings.Cut(p, "=")
		if strings.EqualFold(strings.TrimSpace(k), "q") {
			q, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			return err == nil && q == 0
		}
	}
	return false
}

func addVary(h http.Header, field string) {
	for _, v := range h.Values("Vary") {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f == "*" || strings.EqualFold(f, field) {
				return
			}
		}
	}
	h.Add("Vary", field)
}

// markGzip turns the headers of an identity response into those of its
// gzip encoding. The ETag becomes weak because the bytes differ, and range
// requests are no longer offered on the transformed body.
func markGzip(h http.Header) {
	h.Set("Content-Encoding", "gzip")
	h.Del("Content-Length")
	h.Del("Accept-Ranges")
	if et := h.Get("ETag"); et != "" && !strings.HasPrefix(et, "W/") {
		h.Set("ETag", "W/"+et)
	}
	addVary(h, "Accept-Encoding")
}

// compressRequest reports whether the response to r may pass through a
// gzipWriter. Upgrades (WebSockets) hijack the connection and are skipped.
func compressRequest(s *siteRT, r *http.Request) bool {
	return s.site.Compress && r.Header.Get("Upgrade") == ""
}

// gzipWriter compresses a response when its headers allow it. Unwrap lets
// http.ResponseController reach the statusWriter and the connection below.
type gzipWriter struct {
	http.ResponseWriter
	accept      bool // client takes gzip and the response has a body
	wroteHeader bool
	zw          *gzip.Writer
}

func newGzipWriter(w http.ResponseWriter, r *http.Request) *gzipWriter {
	return &gzipWriter{ResponseWriter: w, accept: r.Method != http.MethodHead && acceptsGzip(r)}
}

func (g *gzipWriter) WriteHeader(code int) {
	// 1xx (e.g. 103 Early Hints) precede the real response.
	if g.wroteHeader || code < 200 {
		g.ResponseWriter.WriteHeader(code)
		return
	}
	g.wroteHeader = true
	h := g.Header()
	if ce := h.Get("Content-Encoding"); (ce == "" || ce == "identity") && compressibleType(h.Get("Content-Type")) {
		addVary(h, "Accept-Encoding")
		if g.accept && compressStatus(code) && bigEnough(h) {
			markGzip(h)
			g.zw = gzipPool.Get().(*gzip.Writer)
			g.zw.Reset(g.ResponseWriter)
		}
	}
	g.ResponseWriter.WriteHeader(code)
}

// compressStatus excludes responses without a body or with a partial one.
func compressStatus(code int) bool {
	switch {
	case code == http.StatusNoContent || code == http.StatusPartialContent:
		return false
	case code >= 300 && code < 400:
		return false
	}
	return true
}

func bigEnough(h http.Header) bool {
	n, err := strconv.ParseInt(h.Get("Content-Length"), 10, 64)
	return err != nil || n >= minCompressSize
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	if g.zw != nil {
		return g.zw.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

// Flush pushes compressed data out so streamed responses are not held back.
func (g *gzipWriter) Flush() {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	if g.zw != nil {
		_ = g.zw.Flush()
	}
	_ = http.NewResponseController(g.ResponseWriter).Flush()
}

func (g *gzipWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// Close finishes the gzip stream; it must run before the handler returns.
func (g *gzipWriter) Close() {
	if g.zw == nil {
		return
	}
	_ = g.zw.Close()
	g.zw.Reset(io.Discard) // drop the reference to the connection
	gzipPool.Put(g.zw)
	g.zw = nil
}
