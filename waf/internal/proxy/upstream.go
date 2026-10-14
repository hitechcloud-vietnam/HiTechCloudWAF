package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type ctxKey struct{}

type ctxVal struct {
	ip  net.IP
	tls bool
	// fill is set when the response should be stored in the cache.
	fill *cacheFillReq
}

const hstsValue = "max-age=31536000; includeSubDomains"

type readCloser struct {
	io.Reader
	c io.Closer
}

func (r readCloser) Close() error { return r.c.Close() }

func ioMulti(a, b io.Reader) io.Reader { return io.MultiReader(a, b) }

// hop-by-hop and spoofable headers replaced before proxying
var forwardHeaders = []string{"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Real-IP", "Forwarded"}

const downFor = 10 * time.Second

func (e *Engine) newUpstream(s *siteRT, u *url.URL) *upstream {
	up := &upstream{url: u}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   128,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: s.site.UpstreamInsecure}, //nolint:gosec // per-site opt-in
	}
	hostOverride := s.site.UpstreamHost
	up.proxy = &httputil.ReverseProxy{
		Transport:     tr,
		FlushInterval: -1, // stream responses (SSE, long polling)
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.Host = pr.In.Host
			if hostOverride != "" {
				pr.Out.Host = hostOverride
			}
			v, _ := pr.In.Context().Value(ctxKey{}).(ctxVal)
			for _, h := range forwardHeaders {
				pr.Out.Header.Del(h)
			}
			if v.ip != nil {
				prior := ""
				// Keep the chain only when it came through a trusted proxy.
				if peer := remoteIP(pr.In.RemoteAddr); peer != nil && contains(e.opt.TrustedProxies, peer) {
					prior = pr.In.Header.Get("X-Forwarded-For")
				}
				xff := v.ip.String()
				if prior != "" {
					xff = prior + ", " + remoteIP(pr.In.RemoteAddr).String()
				}
				pr.Out.Header.Set("X-Forwarded-For", xff)
				pr.Out.Header.Set("X-Real-IP", v.ip.String())
			}
			proto := "http"
			if v.tls {
				proto = "https"
			}
			pr.Out.Header.Set("X-Forwarded-Proto", proto)
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			if dyn := s.site.Dynamic; v.fill != nil || ((dyn.HTML || dyn.JS) && pathMatches(pr.In.URL.Path, dyn.Paths)) {
				// Let the transport negotiate and transparently decompress
				// gzip so the body can be rewritten, or cached in a form
				// every client can take.
				pr.Out.Header.Del("Accept-Encoding")
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			v, _ := resp.Request.Context().Value(ctxKey{}).(ctxVal)
			if v.tls && s.site.HSTS {
				resp.Header.Set("Strict-Transport-Security", hstsValue)
			}
			if dyn := s.site.Dynamic; dyn.HTML || dyn.JS {
				if err := applyDynamic(dyn, resp); err != nil {
					return err
				}
			}
			// After dynamic protection, so its per-response output (marked
			// X-HCW-Protected) is seen and never stored.
			if v.fill != nil {
				e.fillCache(s, v.fill, resp)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			up.downUntil.Store(time.Now().Add(downFor).UnixNano())
			infoOf(r).set("error")
			e.opt.Log.Warn("upstream error", "site", s.site.ID, "upstream", u.String(), "err", err)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "502 Bad Gateway – upstream unavailable\n")
		},
	}
	return up
}

func remoteIP(addr string) net.IP {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		h = addr
	}
	return net.ParseIP(strings.Trim(h, "[]"))
}

// pick returns the next usable upstream round-robin: not failed by the
// active health check and not recently erroring. When none qualifies it
// still tries one rather than failing every request.
func (s *siteRT) pick() *upstream {
	n := len(s.upstreams)
	if n == 0 {
		return nil
	}
	start := int(s.rr.Add(1))
	now := time.Now().UnixNano()
	for i := 0; i < n; i++ {
		u := s.upstreams[(start+i)%n]
		if !u.unhealthy.Load() && u.downUntil.Load() < now {
			return u
		}
	}
	for i := 0; i < n; i++ {
		u := s.upstreams[(start+i)%n]
		if !u.unhealthy.Load() {
			return u
		}
	}
	return s.upstreams[start%n]
}
