package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func (c *fakeClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func assetBody(uri string, size int) string {
	b := "asset " + uri + " "
	return b + strings.Repeat("x", max(0, size-len(b)))
}

// staticOrigin serves assets whose cache behaviour is chosen by file name,
// counting the requests that reach it.
func staticOrigin(h *harness) *atomic.Int64 {
	var hits atomic.Int64
	h.origin.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		ct := mime.TypeByExtension(path.Ext(r.URL.Path))
		if ct == "" {
			ct = "text/plain; charset=utf-8"
		}
		hd := w.Header()
		hd.Set("Content-Type", ct)
		hd.Set("ETag", `"v1"`)
		size, status, stream := 1500, http.StatusOK, false
		switch path.Base(r.URL.Path) {
		case "cookie.css":
			hd.Set("Set-Cookie", "sid=abc; Path=/")
		case "private.css":
			hd.Set("Cache-Control", "private, max-age=600")
		case "nostore.css":
			hd.Set("Cache-Control", "no-store")
		case "maxage0.css":
			hd.Set("Cache-Control", "public, max-age=0")
		case "vary.css":
			hd.Set("Vary", "Cookie")
		case "missing.css":
			status = http.StatusNotFound
		case "big.css":
			size = 10 << 10
		case "bigstream.css":
			size, stream = 10<<10, true
		case "stream.css":
			stream = true
		case "short.css":
			hd.Set("Cache-Control", "public, max-age=10")
		case "smaxage.css":
			hd.Set("Cache-Control", "max-age=5, s-maxage=100")
		}
		body := assetBody(r.URL.RequestURI(), size)
		if !stream {
			hd.Set("Content-Length", strconv.Itoa(len(body)))
		}
		w.WriteHeader(status)
		if stream {
			// Two writes with a flush: chunked, length unknown upstream.
			half := len(body) / 2
			_, _ = w.Write([]byte(body[:half]))
			http.NewResponseController(w).Flush()
			_, _ = w.Write([]byte(body[half:]))
			return
		}
		_, _ = w.Write([]byte(body))
	})
	return &hits
}

func cacheSite(name string) model.Site {
	return model.Site{ServerNames: []string{name}, Cache: model.CacheConfig{Enabled: true}}
}

// fetch performs a request and returns the cache header with the body.
func (h *harness) fetch(t *testing.T, method, host, uri string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	return h.do(t, method, host, uri, nil, nil, hdr)
}

func TestCacheHitAndMiss(t *testing.T) {
	h := newHarness(t, nil, cacheSite("c.vn"))
	hits := staticOrigin(h)
	ml := &memLog{}
	h.eng.opt.Access = ml

	resp, first := h.fetch(t, "GET", "c.vn", "/static/app.css", nil)
	if resp.StatusCode != 200 || resp.Header.Get("X-HCW-Cache") != "MISS" || hits.Load() != 1 {
		t.Fatalf("first request: %d %q hits=%d", resp.StatusCode, resp.Header.Get("X-HCW-Cache"), hits.Load())
	}
	resp, second := h.fetch(t, "GET", "c.vn", "/static/app.css", nil)
	if resp.Header.Get("X-HCW-Cache") != "HIT" || second != first || hits.Load() != 1 {
		t.Fatalf("second request not a hit: %q hits=%d", resp.Header.Get("X-HCW-Cache"), hits.Load())
	}
	if resp.Header.Get("Age") != "0" || resp.Header.Get("ETag") != `"v1"` || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/css") || resp.ContentLength != int64(len(first)) {
		t.Fatalf("hit headers = %v", resp.Header)
	}
	if e := ml.next(t, 2); e.Action != "cached" || e.Status != 200 || e.Bytes != int64(len(first)) {
		t.Fatalf("access log of a hit = %+v", e)
	}

	// HEAD is answered from the GET entry, without a body.
	resp, body := h.fetch(t, "HEAD", "c.vn", "/static/app.css", nil)
	if resp.Header.Get("X-HCW-Cache") != "HIT" || body != "" || resp.ContentLength != int64(len(first)) {
		t.Fatalf("HEAD: %q %q len=%d", resp.Header.Get("X-HCW-Cache"), body, resp.ContentLength)
	}
	// Revalidation of a cached object.
	resp, _ = h.fetch(t, "GET", "c.vn", "/static/app.css", map[string]string{"If-None-Match": `"v0", "v1"`})
	if resp.StatusCode != http.StatusNotModified || resp.Header.Get("X-HCW-Cache") != "HIT" {
		t.Fatalf("If-None-Match: %d", resp.StatusCode)
	}
	if hits.Load() != 1 {
		t.Fatalf("origin reached %d times", hits.Load())
	}

	// The query is part of the key.
	if resp, _ := h.fetch(t, "GET", "c.vn", "/static/app.css?v=2", nil); resp.Header.Get("X-HCW-Cache") != "MISS" || hits.Load() != 2 {
		t.Fatal("other query served from cache")
	}
	// Extensions outside the list are never cached.
	for i := 0; i < 2; i++ {
		if resp, _ := h.fetch(t, "GET", "c.vn", "/index.html", nil); resp.Header.Get("X-HCW-Cache") != "" {
			t.Fatalf("html cached: %q", resp.Header.Get("X-HCW-Cache"))
		}
	}
	// A HEAD miss is proxied but stores nothing.
	h.fetch(t, "HEAD", "c.vn", "/static/head.css", nil)
	if resp, _ := h.fetch(t, "GET", "c.vn", "/static/head.css", nil); resp.Header.Get("X-HCW-Cache") != "MISS" {
		t.Fatal("HEAD response was stored")
	}
	// Bodies of unknown length are stored once complete.
	h.fetch(t, "GET", "c.vn", "/static/stream.css", nil)
	if resp, b := h.fetch(t, "GET", "c.vn", "/static/stream.css", nil); resp.Header.Get("X-HCW-Cache") != "HIT" || b != assetBody("/static/stream.css", 1500) {
		t.Fatalf("streamed body: %q", resp.Header.Get("X-HCW-Cache"))
	}
}

func TestCacheOtherHostOrSiteMisses(t *testing.T) {
	a := cacheSite("a.vn")
	a.ServerNames = append(a.ServerNames, "www.a.vn")
	h := newHarness(t, nil, a, cacheSite("b.vn"))
	hits := staticOrigin(h)
	for _, host := range []string{"a.vn", "www.a.vn", "b.vn"} {
		if resp, _ := h.fetch(t, "GET", host, "/s.css", nil); resp.Header.Get("X-HCW-Cache") != "MISS" {
			t.Fatalf("%s: shared an entry", host)
		}
	}
	if hits.Load() != 3 {
		t.Fatalf("hits = %d", hits.Load())
	}
}

func TestCacheTTLAndMaxAge(t *testing.T) {
	s := cacheSite("t.vn")
	s.Cache.TTLSec = 60
	h := newHarness(t, nil, s)
	hits := staticOrigin(h)
	clk := newFakeClock()
	h.eng.cache.setClock(clk.Now)
	state := func(uri string) string {
		t.Helper()
		resp, _ := h.fetch(t, "GET", "t.vn", uri, nil)
		return resp.Header.Get("X-HCW-Cache")
	}

	state("/a.css")
	clk.Add(59 * time.Second)
	if resp, _ := h.fetch(t, "GET", "t.vn", "/a.css", nil); resp.Header.Get("X-HCW-Cache") != "HIT" || resp.Header.Get("Age") != "59" {
		t.Fatalf("before ttl: %q age %q", resp.Header.Get("X-HCW-Cache"), resp.Header.Get("Age"))
	}
	clk.Add(2 * time.Second)
	if got := state("/a.css"); got != "MISS" || hits.Load() != 2 {
		t.Fatalf("after ttl: %q hits=%d", got, hits.Load())
	}

	// A shorter upstream max-age wins over the site TTL.
	state("/short.css")
	clk.Add(9 * time.Second)
	if got := state("/short.css"); got != "HIT" {
		t.Fatalf("short before max-age: %q", got)
	}
	clk.Add(2 * time.Second)
	if got := state("/short.css"); got != "MISS" {
		t.Fatalf("short after max-age: %q", got)
	}
	// s-maxage overrides max-age for a shared cache, capped by the TTL.
	state("/smaxage.css")
	clk.Add(30 * time.Second)
	if got := state("/smaxage.css"); got != "HIT" {
		t.Fatalf("s-maxage: %q", got)
	}
	clk.Add(31 * time.Second)
	if got := state("/smaxage.css"); got != "MISS" {
		t.Fatalf("s-maxage beyond ttl: %q", got)
	}
	// Expired entries are also swept in the background.
	clk.Add(time.Hour)
	h.eng.cache.gc()
	if n, b := h.eng.CacheStats(); n != 0 || b != 0 {
		t.Fatalf("after gc: %d objects, %d bytes", n, b)
	}
}

func TestCacheSkipsUncacheable(t *testing.T) {
	s := cacheSite("u.vn")
	s.Cache.MaxObjectKB = 4
	s.Dynamic = model.DynamicProtection{JS: true, Paths: []string{"/protected/"}}
	h := newHarness(t, nil, s)
	hits := staticOrigin(h)
	cases := []struct {
		name, method, uri string
		hdr               map[string]string
	}{
		{"set-cookie", "GET", "/static/cookie.css", nil},
		{"private", "GET", "/static/private.css", nil},
		{"no-store", "GET", "/static/nostore.css", nil},
		{"max-age=0", "GET", "/static/maxage0.css", nil},
		{"vary cookie", "GET", "/static/vary.css", nil},
		{"404", "GET", "/static/missing.css", nil},
		{"oversize", "GET", "/static/big.css", nil},
		{"oversize stream", "GET", "/static/bigstream.css", nil},
		{"dynamic protected", "GET", "/protected/app.js", nil},
		{"authorization", "GET", "/static/a.css", map[string]string{"Authorization": "Bearer abcdef"}},
		{"range", "GET", "/static/b.css", map[string]string{"Range": "bytes=0-10"}},
		{"post", "POST", "/static/c.css", nil},
	}
	for _, c := range cases {
		before := hits.Load()
		for i := 0; i < 2; i++ {
			resp, _ := h.fetch(t, c.method, "u.vn", c.uri, c.hdr)
			if resp.Header.Get("X-HCW-Cache") == "HIT" {
				t.Errorf("%s: served from cache", c.name)
			}
		}
		if got := hits.Load() - before; got != 2 {
			t.Errorf("%s: origin reached %d times, want 2", c.name, got)
		}
	}
	if n, _ := h.eng.CacheStats(); n != 0 {
		t.Fatalf("%d objects stored", n)
	}
	// A POST must not populate the GET entry either.
	if resp, _ := h.fetch(t, "GET", "u.vn", "/static/c.css", nil); resp.Header.Get("X-HCW-Cache") != "MISS" {
		t.Fatal("GET after POST was not a miss")
	}
}

func TestCacheLRU(t *testing.T) {
	ent := func(k string) *cacheEntry { return &cacheEntry{key: k, body: make([]byte, 1000)} }
	one := entrySize(ent("a"))
	c := newRespCache(3*one + 10)
	for _, k := range []string{"a", "b", "c"} {
		c.put(ent(k), time.Hour)
	}
	if e, _ := c.get("a"); e == nil { // a becomes the most recently used
		t.Fatal("a missing")
	}
	c.put(ent("d"), time.Hour)
	if e, _ := c.get("b"); e != nil {
		t.Fatal("least recently used entry b was not evicted")
	}
	for _, k := range []string{"a", "c", "d"} {
		if e, _ := c.get(k); e == nil {
			t.Fatalf("%s evicted", k)
		}
	}
	if n, used := c.stats(); n != 3 || used != 3*one {
		t.Fatalf("stats = %d, %d", n, used)
	}
	c.put(ent("a"), time.Hour) // replacing does not double count
	if _, used := c.stats(); used != 3*one {
		t.Fatalf("used after replace = %d", used)
	}
	c.put(&cacheEntry{key: "huge", body: make([]byte, 4*one)}, time.Hour)
	if n, _ := c.stats(); n != 3 {
		t.Fatal("an object larger than the budget evicted others")
	}
}

// All sites share one budget: filling it on one evicts the coldest objects.
func TestCacheEvictionThroughEngine(t *testing.T) {
	h := newHarness(t, nil, cacheSite("l1.vn"), cacheSite("l2.vn"))
	staticOrigin(h)
	h.eng.cache = newRespCache(5000) // room for two ~2 KB objects
	state := func(host, uri string) string {
		t.Helper()
		resp, _ := h.fetch(t, "GET", host, uri, nil)
		return resp.Header.Get("X-HCW-Cache")
	}
	state("l1.vn", "/a.css")
	state("l2.vn", "/b.css")
	if state("l1.vn", "/a.css") != "HIT" {
		t.Fatal("a not cached")
	}
	state("l2.vn", "/c.css") // evicts b, the least recently used
	if got := state("l1.vn", "/a.css"); got != "HIT" {
		t.Fatalf("a: %q", got)
	}
	if got := state("l2.vn", "/b.css"); got != "MISS" {
		t.Fatalf("b: %q, want evicted", got)
	}
	if _, used := h.eng.CacheStats(); used > 5000 {
		t.Fatalf("budget exceeded: %d", used)
	}
}

func TestCachePurge(t *testing.T) {
	h := newHarness(t, nil, cacheSite("p1.vn"), cacheSite("p2.vn"))
	staticOrigin(h)
	for _, u := range []string{"/static/a.css", "/static/b.css?v=1", "/img/x.png"} {
		h.fetch(t, "GET", "p1.vn", u, nil)
	}
	h.fetch(t, "GET", "p2.vn", "/static/a.css", nil)

	if n := h.eng.PurgeCache(1, "/static/"); n != 2 {
		t.Fatalf("purged %d, want 2", n)
	}
	want := map[[2]string]string{
		{"p1.vn", "/static/a.css"}: "MISS",
		{"p1.vn", "/img/x.png"}:    "HIT",
		{"p2.vn", "/static/a.css"}: "HIT",
	}
	for k, v := range want {
		if resp, _ := h.fetch(t, "GET", k[0], k[1], nil); resp.Header.Get("X-HCW-Cache") != v {
			t.Errorf("%v after purge: %q, want %s", k, resp.Header.Get("X-HCW-Cache"), v)
		}
	}
	if n := h.eng.PurgeCache(0, ""); n != 3 {
		t.Fatalf("purge all removed %d, want 3", n)
	}
	if n, b := h.eng.CacheStats(); n != 0 || b != 0 {
		t.Fatalf("after purge: %d objects, %d bytes", n, b)
	}
}

// Security checks run before the cache: a cached URL does not let attacks
// or denied clients through.
func TestCacheDoesNotBypassWAF(t *testing.T) {
	h := newHarness(t, nil, cacheSite("w.vn"))
	hits := staticOrigin(h)
	h.fetch(t, "GET", "w.vn", "/static/app.js", nil)
	if resp, _ := h.fetch(t, "GET", "w.vn", "/static/app.js", nil); resp.Header.Get("X-HCW-Cache") != "HIT" {
		t.Fatal("not cached")
	}
	attacks := []struct {
		uri string
		hdr map[string]string
	}{
		{"/static/app.js", map[string]string{"Cookie": "id=1' UNION SELECT username,password FROM users--"}},
		{"/static/app.js?q=" + url.QueryEscape("<script>alert(document.cookie)</script>"), nil},
	}
	for _, a := range attacks {
		if resp, _ := h.fetch(t, "GET", "w.vn", a.uri, a.hdr); resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-HCW-Cache") != "" {
			t.Errorf("attack on cached path %s: %d %q", a.uri, resp.StatusCode, resp.Header.Get("X-HCW-Cache"))
		}
	}
	if hits.Load() != 1 || len(h.ev.Latest(10, 0)) != 2 {
		t.Fatalf("hits=%d events=%d", hits.Load(), len(h.ev.Latest(10, 0)))
	}
}

func TestCacheDroppedOnConfigChange(t *testing.T) {
	h := newHarness(t, nil, cacheSite("r.vn"))
	staticOrigin(h)
	h.fetch(t, "GET", "r.vn", "/a.css", nil)
	s := h.eng.rt.Load().ports[h.port].exact["r.vn"].site

	// Re-applying the same configuration keeps the objects.
	if err := h.eng.Apply([]model.Site{s}, nil); err != nil {
		t.Fatal(err)
	}
	if resp, _ := h.fetch(t, "GET", "r.vn", "/a.css", nil); resp.Header.Get("X-HCW-Cache") != "HIT" {
		t.Fatal("unchanged site lost its cache")
	}
	s.Dynamic.JS = true
	if err := h.eng.Apply([]model.Site{s}, nil); err != nil {
		t.Fatal(err)
	}
	if n, _ := h.eng.CacheStats(); n != 0 {
		t.Fatal("changed site kept its cache")
	}
}

func TestCacheTTLDirectives(t *testing.T) {
	c := &model.CacheConfig{Enabled: true, TTLSec: 300}
	req, _ := http.NewRequest("GET", "http://x/a.css", nil)
	cases := []struct {
		hdr  map[string]string
		want time.Duration
	}{
		{nil, 300 * time.Second},
		{map[string]string{"Cache-Control": "public, max-age=60"}, 60 * time.Second},
		{map[string]string{"Cache-Control": "max-age=9999"}, 300 * time.Second},
		{map[string]string{"Cache-Control": `max-age="30"`}, 30 * time.Second},
		{map[string]string{"Cache-Control": "max-age=60, s-maxage=120"}, 120 * time.Second},
		{map[string]string{"Cache-Control": "no-cache"}, 0},
		{map[string]string{"Cache-Control": `private="x"`}, 0},
		{map[string]string{"Cache-Control": "Public, No-Store"}, 0},
		{map[string]string{"Vary": "Accept-Encoding"}, 300 * time.Second},
		{map[string]string{"Vary": "*"}, 0},
		{map[string]string{"Content-Encoding": "gzip"}, 0},
		{map[string]string{"X-HCW-Protected": "js"}, 0},
	}
	for i, k := range cases {
		resp := &http.Response{StatusCode: 200, Header: http.Header{}, Request: req}
		for h, v := range k.hdr {
			resp.Header.Set(h, v)
		}
		if got := cacheTTL(c, resp); got != k.want {
			t.Errorf("case %d %v: %v, want %v", i, k.hdr, got, k.want)
		}
	}
	h := storedHeader(http.Header{"Strict-Transport-Security": {"max-age=1"}, "Content-Length": {"9"}, "Content-Type": {"text/css"}})
	if len(h) != 1 || h.Get("Content-Type") != "text/css" {
		t.Fatalf("stored header = %v", h)
	}
}

func TestCacheConfigNormalize(t *testing.T) {
	c := model.CacheConfig{Enabled: true, Extensions: []string{"CSS", ".Js "}}
	if err := (&model.Site{ServerNames: []string{"n.vn"}, Upstreams: []string{"http://127.0.0.1:1"}, Cache: c}).Normalize(); err != nil {
		t.Fatal(err)
	}
	s := model.Site{ServerNames: []string{"n.vn"}, Upstreams: []string{"http://127.0.0.1:1"}, Cache: c}
	_ = s.Normalize()
	if s.Cache.TTLSec != 300 || s.Cache.MaxObjectKB != 1024 || strings.Join(s.Cache.Extensions, ",") != ".css,.js" {
		t.Fatalf("normalized = %+v", s.Cache)
	}
	s = model.Site{ServerNames: []string{"n.vn"}, Upstreams: []string{"http://127.0.0.1:1"}}
	_ = s.Normalize()
	if len(s.Cache.Extensions) != len(model.DefaultCacheExtensions) {
		t.Fatalf("default extensions = %v", s.Cache.Extensions)
	}
	for _, bad := range []model.CacheConfig{{TTLSec: 86401}, {TTLSec: -1}, {MaxObjectKB: 200000}, {Paths: []string{"static/"}}, {Extensions: []string{".tar.gz"}}} {
		s := model.Site{ServerNames: []string{"n.vn"}, Upstreams: []string{"http://127.0.0.1:1"}, Cache: bad}
		if err := s.Normalize(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestCachePathsMode(t *testing.T) {
	s := cacheSite("pm.vn")
	s.Cache.Paths = []string{"/assets/"}
	h := newHarness(t, nil, s)
	staticOrigin(h)
	h.fetch(t, "GET", "pm.vn", "/assets/data", nil)
	if resp, _ := h.fetch(t, "GET", "pm.vn", "/assets/data", nil); resp.Header.Get("X-HCW-Cache") != "HIT" {
		t.Fatal("path prefix not cached")
	}
	if resp, _ := h.fetch(t, "GET", "pm.vn", "/other/app.css", nil); resp.Header.Get("X-HCW-Cache") != "" {
		t.Fatal("extension outside the paths cached")
	}
}

// HSTS is added per request: an object cached over HTTPS carries it there
// and never leaks it to plain HTTP (which has its own entry).
func TestCacheHSTSPerScheme(t *testing.T) {
	ev, _ := events.New(10, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng := New(ctx, Options{Bind: "127.0.0.1", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Events: ev})
	defer eng.Shutdown(context.Background())
	h := &harness{eng: eng, origin: httptest.NewServer(http.NotFoundHandler())}
	defer h.origin.Close()
	hits := staticOrigin(h)

	crt, key := selfSigned(t, "s.vn")
	certs := []model.Cert{{ID: 1, Crt: crt, Key: key}}
	if err := certs[0].Normalize(); err != nil {
		t.Fatal(err)
	}
	plain, secure := freePort(t), freePort(t)
	site := model.Site{ID: 1, ServerNames: []string{"s.vn"}, Ports: []string{strconv.Itoa(plain), fmt.Sprintf("%d_ssl", secure)},
		CertID: 1, Upstreams: []string{h.origin.URL}, HSTS: true, Cache: model.CacheConfig{Enabled: true}}
	if err := site.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := eng.Apply([]model.Site{site}, certs); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "s.vn", InsecureSkipVerify: true}}} //nolint:gosec // test
	get := func(scheme string, port int) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s://127.0.0.1:%d/a.css", scheme, port), nil)
		req.Host = "s.vn"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}
	get("https", secure)
	if resp := get("https", secure); resp.Header.Get("X-HCW-Cache") != "HIT" || resp.Header.Get("Strict-Transport-Security") == "" {
		t.Fatalf("https hit: %v", resp.Header)
	}
	if resp := get("http", plain); resp.Header.Get("X-HCW-Cache") != "MISS" || resp.Header.Get("Strict-Transport-Security") != "" {
		t.Fatalf("http after https: %v", resp.Header)
	}
	if resp := get("http", plain); resp.Header.Get("X-HCW-Cache") != "HIT" || resp.Header.Get("Strict-Transport-Security") != "" {
		t.Fatalf("http hit: %v", resp.Header)
	}
	if hits.Load() != 2 {
		t.Fatalf("origin reached %d times", hits.Load())
	}
}
