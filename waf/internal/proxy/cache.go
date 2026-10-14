package proxy

import (
	"container/list"
	"io"
	"net/http"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

// Response cache: sites with cache.enabled keep copies of static upstream
// responses in memory. All sites share one LRU with a global byte budget
// (Options.CacheMB), so a busy site cannot grow the node's memory without
// bound; it can only push other sites' cold objects out.
//
// Hits are served after the ACL, rate limits, challenges and the WAF have
// run (see serveSite), so caching never weakens protection; it only saves
// the trip to the origin.
//
// Bodies are stored uncompressed (the upstream request drops the client's
// Accept-Encoding so the transport decodes gzip). When the site also has
// compress on, a gzip copy is made once at store time and served to clients
// that accept it, so hits do not pay for compression on every request.

const (
	defaultCacheMB = 256
	// cacheEntryOverhead approximates the bookkeeping of one entry, so many
	// tiny objects are still charged against the budget.
	cacheEntryOverhead = 256
)

type cacheEntry struct {
	key    string
	site   int
	uri    string // request URI (path and query), matched by PurgeCache
	header http.Header
	body   []byte
	gzip   []byte // gzip copy of body, nil when not compressible
	size   int64

	stored  time.Time
	expires time.Time
}

// respCache is an LRU of upstream responses. Entries are immutable once
// stored, so a hit can be written without holding the lock.
type respCache struct {
	mu     sync.Mutex
	budget int64
	used   int64
	lru    *list.List // front = most recently used; values are *cacheEntry
	items  map[string]*list.Element
	now    func() time.Time // replaced by tests
}

func newRespCache(budget int64) *respCache {
	return &respCache{budget: budget, lru: list.New(), items: map[string]*list.Element{}, now: time.Now}
}

func (c *respCache) setClock(now func() time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

// get returns the live entry for key and its age, or nil.
func (c *respCache) get(key string) (*cacheEntry, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el := c.items[key]
	if el == nil {
		return nil, 0
	}
	ent := el.Value.(*cacheEntry)
	now := c.now()
	if !now.Before(ent.expires) {
		c.remove(el)
		return nil, 0
	}
	c.lru.MoveToFront(el)
	return ent, now.Sub(ent.stored)
}

// put stores ent for ttl, evicting the least recently used entries until it
// fits. Objects larger than the whole budget are not stored.
func (c *respCache) put(ent *cacheEntry, ttl time.Duration) {
	ent.size = entrySize(ent)
	if ent.size > c.budget {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ent.stored = c.now()
	ent.expires = ent.stored.Add(ttl)
	if old := c.items[ent.key]; old != nil {
		c.remove(old)
	}
	for c.used+ent.size > c.budget {
		c.remove(c.lru.Back())
	}
	c.items[ent.key] = c.lru.PushFront(ent)
	c.used += ent.size
}

func (c *respCache) remove(el *list.Element) {
	ent := c.lru.Remove(el).(*cacheEntry)
	delete(c.items, ent.key)
	c.used -= ent.size
}

// purge removes the entries match selects and returns how many.
func (c *respCache) purge(match func(*cacheEntry) bool) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for el := c.lru.Front(); el != nil; {
		next := el.Next()
		if match(el.Value.(*cacheEntry)) {
			c.remove(el)
			n++
		}
		el = next
	}
	return n
}

// gc drops expired entries so they do not hold memory until evicted.
func (c *respCache) gc() {
	c.mu.Lock()
	now := c.now()
	c.mu.Unlock()
	c.purge(func(ent *cacheEntry) bool { return !now.Before(ent.expires) })
}

func (c *respCache) stats() (objects int, bytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items), c.used
}

func entrySize(ent *cacheEntry) int64 {
	n := cacheEntryOverhead + len(ent.key) + len(ent.uri) + len(ent.body) + len(ent.gzip)
	for k, vs := range ent.header {
		n += len(k)
		for _, v := range vs {
			n += len(v)
		}
	}
	return int64(n)
}

// PurgeCache removes cached responses of site siteID (0 = every site)
// whose request URI (path and query) starts with prefix ("" = everything).
// It returns the number of objects removed.
func (e *Engine) PurgeCache(siteID int, prefix string) int {
	if e.cache == nil {
		return 0
	}
	return e.cache.purge(func(ent *cacheEntry) bool {
		return (siteID == 0 || ent.site == siteID) && strings.HasPrefix(ent.uri, prefix)
	})
}

// CacheStats reports the number of cached objects and the bytes they use.
func (e *Engine) CacheStats() (objects int, bytes int64) {
	if e.cache == nil {
		return 0, 0
	}
	return e.cache.stats()
}

// retainCache drops the objects of sites that were removed, turned their
// cache off or changed configuration (new upstream, dynamic protection
// switched on, ...), so a new configuration never serves content produced
// under the old one.
func (e *Engine) retainCache(prev []*siteRT, sites []model.Site) {
	if e.cache == nil {
		return
	}
	keep := map[int]bool{}
	for _, old := range prev {
		for i := range sites {
			if s := &sites[i]; s.ID == old.site.ID && s.Cache.Enabled && reflect.DeepEqual(*s, old.site) {
				keep[s.ID] = true
			}
		}
	}
	e.cache.purge(func(ent *cacheEntry) bool { return !keep[ent.site] })
}

// cacheableRequest reports whether r may be answered from the cache.
func cacheableRequest(c *model.CacheConfig, r *http.Request) bool {
	if !c.Enabled || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return false
	}
	// Credentials mean a personalised answer; ranges a partial one;
	// upgrades are not responses at all.
	if r.Header.Get("Authorization") != "" || r.Header.Get("Range") != "" || r.Header.Get("Upgrade") != "" {
		return false
	}
	if len(c.Paths) > 0 {
		return pathMatches(r.URL.Path, c.Paths)
	}
	ext := strings.ToLower(path.Ext(r.URL.Path))
	return ext != "" && slices.Contains(c.Extensions, ext)
}

// cacheKey identifies a response. HEAD shares the GET entry: it is the
// same response without the body. The scheme is part of the key because
// the upstream sees it (X-Forwarded-Proto) and may answer differently.
func cacheKey(siteID int, r *http.Request) string {
	method := r.Method
	if method == http.MethodHead {
		method = http.MethodGet
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return strconv.Itoa(siteID) + "\x00" + scheme + "://" + strings.ToLower(r.Host) + "\x00" + method + "\x00" + r.URL.RequestURI()
}

// cacheFillReq travels with a request whose response should be stored.
type cacheFillReq struct {
	key string
	uri string
}

// storeRequest returns what fillCache needs to store r's response, or nil.
// Only GET responses are stored: a HEAD response has no body to keep.
func (e *Engine) storeRequest(s *siteRT, r *http.Request) *cacheFillReq {
	if e.cache == nil || r.Method != http.MethodGet || !cacheableRequest(&s.site.Cache, r) {
		return nil
	}
	return &cacheFillReq{key: cacheKey(s.site.ID, r), uri: r.URL.RequestURI()}
}

// cacheTTL returns how long resp may be kept, or 0 when it must not be.
func cacheTTL(c *model.CacheConfig, resp *http.Response) time.Duration {
	if resp.StatusCode != http.StatusOK || resp.Request == nil || resp.Request.Method != http.MethodGet {
		return 0
	}
	h := resp.Header
	// Cookies and dynamically protected pages are per visitor; an encoded
	// body we did not decode cannot be served to everyone.
	if len(h.Values("Set-Cookie")) > 0 || h.Get("X-HCW-Protected") != "" {
		return 0
	}
	if ce := h.Get("Content-Encoding"); ce != "" && ce != "identity" {
		return 0
	}
	if !varyCacheable(h) {
		return 0
	}
	ttl := time.Duration(c.TTLSec) * time.Second
	maxAge, sMaxAge := -1, -1
	for _, v := range h.Values("Cache-Control") {
		for _, d := range strings.Split(v, ",") {
			name, val, _ := strings.Cut(strings.TrimSpace(d), "=")
			n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(val), `"`))
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "private", "no-store", "no-cache":
				return 0
			case "max-age":
				if err == nil {
					maxAge = n
				}
			case "s-maxage":
				if err == nil {
					sMaxAge = n
				}
			}
		}
	}
	// s-maxage is addressed to shared caches like this one.
	if sMaxAge >= 0 {
		maxAge = sMaxAge
	}
	if maxAge >= 0 && time.Duration(maxAge)*time.Second < ttl {
		ttl = time.Duration(maxAge) * time.Second
	}
	return ttl
}

// varyCacheable accepts responses that vary at most by Accept-Encoding:
// the cache always fetches the identity encoding, so that one is moot. Any
// other Vary (Cookie, User-Agent, *) would need one entry per variant.
func varyCacheable(h http.Header) bool {
	for _, v := range h.Values("Vary") {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" && !strings.EqualFold(f, "Accept-Encoding") {
				return false
			}
		}
	}
	return true
}

// storedHeader is the part of the upstream header kept with an entry.
// Headers that depend on the request or the moment are set when serving.
func storedHeader(h http.Header) http.Header {
	out := h.Clone()
	for _, k := range []string{"Strict-Transport-Security", "X-HCW-Cache", "Content-Length", "Age"} {
		out.Del(k)
	}
	return out
}

// fillCache arranges for resp to be stored once its body has been read in
// full while it streams to the client. Truncated or oversize bodies are not
// stored.
func (e *Engine) fillCache(s *siteRT, fr *cacheFillReq, resp *http.Response) {
	c := &s.site.Cache
	ttl := cacheTTL(c, resp)
	limit := int64(c.MaxObjectKB) << 10
	if ttl <= 0 || resp.ContentLength > limit {
		return
	}
	resp.Header.Set("X-HCW-Cache", "MISS")
	hdr := storedHeader(resp.Header)
	siteID, compress := s.site.ID, s.site.Compress
	resp.Body = &cacheFill{ReadCloser: resp.Body, limit: limit, want: resp.ContentLength, done: func(body []byte) {
		ent := &cacheEntry{key: fr.key, site: siteID, uri: fr.uri, header: hdr, body: body}
		if compress && len(body) >= minCompressSize && compressibleType(hdr.Get("Content-Type")) {
			if gz := gzipBytes(body); len(gz) < len(body) {
				ent.gzip = gz
			}
		}
		e.cache.put(ent, ttl)
	}}
}

// cacheFill copies a response body as it is read and hands the copy to
// done when the body ends cleanly.
type cacheFill struct {
	io.ReadCloser
	limit int64
	want  int64 // Content-Length, -1 when unknown
	buf   []byte
	over  bool
	done  func([]byte)
}

func (f *cacheFill) Read(p []byte) (int, error) {
	n, err := f.ReadCloser.Read(p)
	if !f.over && n > 0 {
		if int64(len(f.buf)+n) > f.limit {
			f.over, f.buf = true, nil
		} else {
			f.buf = append(f.buf, p[:n]...)
		}
	}
	if err == io.EOF && !f.over && f.done != nil && (f.want < 0 || int64(len(f.buf)) == f.want) {
		f.done(f.buf)
		f.done = nil
	}
	return n, err
}

// serveCached answers r from the cache and reports whether it did.
func (e *Engine) serveCached(w http.ResponseWriter, r *http.Request, s *siteRT, isTLS bool) bool {
	if e.cache == nil || !cacheableRequest(&s.site.Cache, r) {
		return false
	}
	ent, age := e.cache.get(cacheKey(s.site.ID, r))
	if ent == nil {
		return false
	}
	infoOf(r).set("cached")
	h := w.Header()
	for k, v := range ent.header {
		h[k] = slices.Clone(v)
	}
	h.Set("X-HCW-Cache", "HIT")
	h.Set("Age", strconv.Itoa(int(age/time.Second)))
	if isTLS && s.site.HSTS {
		h.Set("Strict-Transport-Security", hstsValue)
	}
	body := ent.body
	if ent.gzip != nil && s.site.Compress && acceptsGzip(r) {
		body = ent.gzip
		markGzip(h)
	}
	if etagMatches(r.Header.Get("If-None-Match"), h.Get("ETag")) {
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
	return true
}

// etagMatches implements the weak comparison If-None-Match calls for.
func etagMatches(inm, etag string) bool {
	if inm == "" || etag == "" {
		return false
	}
	etag = strings.TrimPrefix(etag, "W/")
	for _, t := range strings.Split(inm, ",") {
		if t = strings.TrimSpace(t); t == "*" || strings.TrimPrefix(t, "W/") == etag {
			return true
		}
	}
	return false
}
