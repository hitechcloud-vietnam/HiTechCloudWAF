// Package proxy is the HiTechCloud WAF data plane: listeners, virtual hosts,
// IP ACL, rate limiting, OWASP CRS inspection and reverse proxying.
package proxy

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/accesslog"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

// Options configure the engine.
type Options struct {
	Bind           string // address to bind site ports on ("" = all)
	BodyLimit      int    // bytes of request body inspected
	TrustedProxies []*net.IPNet
	Brand          Brand
	ExtraRules     string
	// Secret signs challenge cookies. Nodes behind the same DNS name should
	// share it so a visitor keeps their pass when moved between nodes.
	Secret []byte
	// Access receives one entry per request (optional).
	Access interface{ Log(accesslog.Entry) }
	// GeoIP resolves countries for country_allow/deny and events (optional).
	GeoIP  interface{ Country(net.IP) string }
	Log    *slog.Logger
	Events *events.Log
}

type upstream struct {
	url       *url.URL
	proxy     *httputil.ReverseProxy
	downUntil atomic.Int64

	// active health check state
	unhealthy atomic.Bool
	hcMu      sync.Mutex
	fails     int
	oks       int
	lastCheck time.Time
	lastError string
}

type ruleRT struct {
	model.PathRule
	nets []*net.IPNet
}

func (r *ruleRT) matches(req *http.Request, ip net.IP) bool {
	p := req.URL.Path
	if r.Exact {
		if p != r.Path {
			return false
		}
	} else if !strings.HasPrefix(p, r.Path) {
		return false
	}
	if len(r.Methods) > 0 && !hasCode(r.Methods, req.Method) {
		return false
	}
	return len(r.nets) == 0 || contains(r.nets, ip)
}

type siteRT struct {
	rules     []ruleRT
	site      model.Site
	waf       coraza.WAF
	allow     []*net.IPNet
	deny      []*net.IPNet
	upstreams []*upstream
	rr        atomic.Uint32
	httpsPort int
}

type portRT struct {
	port   int
	tls    bool
	exact  map[string]*siteRT
	wild   []wildRoute // "*.example.com", longest suffix first
	any    *siteRT     // server name "_"
	certs  map[string]*tls.Certificate
	defCrt *tls.Certificate
}

type wildRoute struct {
	suffix string // ".example.com"
	site   *siteRT
}

type runtime struct {
	ports map[int]*portRT
}

type listener struct {
	tls bool
	srv *http.Server
}

// CertProvider issues certificates automatically (ACME / Let's Encrypt).
type CertProvider interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// HTTPHandler answers HTTP-01 challenges.
	HTTPHandler(fallback http.Handler) http.Handler
}

// Engine serves all sites.
type Engine struct {
	opt     Options
	pool    *WAFPool
	limiter *limiter
	rt      atomic.Pointer[runtime]

	mu        sync.Mutex
	listeners map[int]*listener
	ctx       context.Context

	acme atomic.Pointer[acmeBox]
}

type acmeBox struct{ p CertProvider }

// SetCertProvider enables automatic certificates for sites with auto_tls.
func (e *Engine) SetCertProvider(p CertProvider) { e.acme.Store(&acmeBox{p}) }

func (e *Engine) certProvider() CertProvider {
	if b := e.acme.Load(); b != nil {
		return b.p
	}
	return nil
}

// ACMEHostPolicy allows certificate requests only for exact server names of
// sites with auto_tls, so nobody can make the node request arbitrary names.
func (e *Engine) ACMEHostPolicy(_ context.Context, host string) error {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pr := range e.rt.Load().ports {
		if s, ok := pr.exact[host]; ok && s.site.AutoTLS {
			return nil
		}
	}
	return fmt.Errorf("acme: %q is not a server name of an auto_tls site", host)
}

// New creates an engine; call Apply to load sites and Start to listen.
func New(ctx context.Context, opt Options) *Engine {
	if opt.BodyLimit <= 0 {
		opt.BodyLimit = 1 << 20
	}
	if opt.Brand.Name == "" {
		opt.Brand.Name = "HiTechCloud WAF"
	}
	if opt.Brand.Color == "" {
		opt.Brand.Color = "#1D4ED8"
	}
	if len(opt.Secret) == 0 {
		opt.Secret = make([]byte, 32)
		_, _ = crand.Read(opt.Secret)
	}
	e := &Engine{opt: opt, pool: NewWAFPool(opt.ExtraRules), limiter: newLimiter(), listeners: map[int]*listener{}, ctx: ctx}
	e.rt.Store(&runtime{ports: map[int]*portRT{}})
	go e.healthLoop(ctx)
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				e.limiter.gc(now, 10*time.Minute)
			}
		}
	}()
	return e
}

// Apply builds a new runtime from sites and certs and swaps it in
// atomically, then opens/closes listeners to match. On error the running
// configuration is left untouched.
func (e *Engine) Apply(sites []model.Site, certs []model.Cert) error {
	certByID := map[int]*tls.Certificate{}
	certDomains := map[int][]string{}
	for _, c := range certs {
		kp, err := c.KeyPair()
		if err != nil {
			return fmt.Errorf("cert %d: %w", c.ID, err)
		}
		k := kp
		certByID[c.ID] = &k
		certDomains[c.ID] = c.Domains
	}
	rt := &runtime{ports: map[int]*portRT{}}
	for i := range sites {
		s := sites[i]
		w, err := e.pool.Get(&s, e.opt.BodyLimit)
		if err != nil {
			return fmt.Errorf("site %d: %w", s.ID, err)
		}
		srt := &siteRT{site: s, waf: w}
		for _, c := range s.IPAllow {
			n, _ := model.ParseCIDR(c)
			srt.allow = append(srt.allow, n)
		}
		for _, c := range s.IPDeny {
			n, _ := model.ParseCIDR(c)
			srt.deny = append(srt.deny, n)
		}
		for _, r := range s.Rules {
			rr := ruleRT{PathRule: r}
			for _, c := range r.IPs {
				n, _ := model.ParseCIDR(c)
				rr.nets = append(rr.nets, n)
			}
			srt.rules = append(srt.rules, rr)
		}
		for _, raw := range s.Upstreams {
			u, err := url.Parse(raw)
			if err != nil {
				return err
			}
			srt.upstreams = append(srt.upstreams, e.newUpstream(srt, u))
		}
		for _, p := range s.Ports {
			n, isTLS, _ := model.ParsePort(p)
			if isTLS && srt.httpsPort == 0 {
				srt.httpsPort = n
			}
		}
		for _, p := range s.Ports {
			n, isTLS, _ := model.ParsePort(p)
			pr, ok := rt.ports[n]
			if !ok {
				pr = &portRT{port: n, tls: isTLS, exact: map[string]*siteRT{}, certs: map[string]*tls.Certificate{}}
				rt.ports[n] = pr
			}
			if pr.tls != isTLS {
				return fmt.Errorf("port %d is used both with and without TLS", n)
			}
			for _, name := range s.ServerNames {
				switch {
				case name == "_":
					pr.any = srt
				case strings.HasPrefix(name, "*."):
					pr.wild = append(pr.wild, wildRoute{suffix: name[1:], site: srt})
				default:
					pr.exact[name] = srt
				}
			}
			if isTLS && !(s.AutoTLS && s.CertID == 0) {
				crt := certByID[s.CertID]
				if crt == nil {
					return fmt.Errorf("site %d: cert %d not found", s.ID, s.CertID)
				}
				for _, d := range append(append([]string{}, certDomains[s.CertID]...), s.ServerNames...) {
					pr.certs[strings.ToLower(d)] = crt
				}
				if pr.defCrt == nil {
					pr.defCrt = crt
				}
			}
		}
	}
	for _, pr := range rt.ports {
		sort.Slice(pr.wild, func(i, j int) bool { return len(pr.wild[i].suffix) > len(pr.wild[j].suffix) })
	}
	carryHealth(e.rt.Load(), rt)
	old := e.rt.Swap(rt)
	e.pool.Retain(sites, e.opt.BodyLimit)
	// Old transports are unreachable now; release their idle connections.
	for _, pr := range old.ports {
		for _, srt := range pr.allSites() {
			for _, u := range srt.upstreams {
				if t, ok := u.proxy.Transport.(*http.Transport); ok {
					t.CloseIdleConnections()
				}
			}
		}
	}
	return e.reconcileListeners(rt)
}

func (e *Engine) reconcileListeners(rt *runtime) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var errs []error
	for port, l := range e.listeners {
		pr, ok := rt.ports[port]
		if ok && pr.tls == l.tls {
			continue
		}
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = l.srv.Shutdown(sh)
		cancel()
		delete(e.listeners, port)
		e.opt.Log.Info("listener closed", "port", port)
	}
	for port, pr := range rt.ports {
		if _, ok := e.listeners[port]; ok {
			continue
		}
		addr := net.JoinHostPort(e.opt.Bind, strconv.Itoa(port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("listen %s: %w", addr, err))
			continue
		}
		srv := &http.Server{
			Handler:           e.handler(port),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    64 << 10,
			ErrorLog:          slog.NewLogLogger(e.opt.Log.Handler(), slog.LevelDebug),
		}
		if pr.tls {
			p := port
			srv.TLSConfig = &tls.Config{
				MinVersion:     tls.VersionTLS12,
				NextProtos:     []string{"h2", "http/1.1", "acme-tls/1"},
				GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) { return e.certFor(p, h) },
			}
			ln = tls.NewListener(ln, srv.TLSConfig)
		}
		e.listeners[port] = &listener{tls: pr.tls, srv: srv}
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				e.opt.Log.Error("listener stopped", "port", port, "err", err)
			}
		}()
		e.opt.Log.Info("listening", "port", port, "tls", pr.tls)
	}
	return errors.Join(errs...)
}

// Shutdown closes all listeners.
func (e *Engine) Shutdown(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for p, l := range e.listeners {
		_ = l.srv.Shutdown(ctx)
		delete(e.listeners, p)
	}
}

func (e *Engine) certFor(port int, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	pr := e.rt.Load().ports[port]
	if pr == nil {
		return nil, errors.New("no site on this port")
	}
	sni := strings.ToLower(hello.ServerName)
	if s, ok := pr.exact[sni]; ok && s.site.AutoTLS {
		if cp := e.certProvider(); cp != nil {
			return cp.GetCertificate(hello)
		}
		return nil, errors.New("auto_tls site but ACME is not configured")
	}
	if c, ok := pr.certs[sni]; ok {
		return c, nil
	}
	if i := strings.IndexByte(sni, '.'); i > 0 {
		if c, ok := pr.certs["*"+sni[i:]]; ok {
			return c, nil
		}
	}
	if pr.defCrt != nil {
		return pr.defCrt, nil
	}
	return nil, errors.New("no certificate")
}

func (pr *portRT) allSites() []*siteRT {
	out := make([]*siteRT, 0, len(pr.exact)+len(pr.wild)+1)
	for _, s := range pr.exact {
		out = append(out, s)
	}
	for _, w := range pr.wild {
		out = append(out, w.site)
	}
	if pr.any != nil {
		out = append(out, pr.any)
	}
	return out
}

func (pr *portRT) route(host string) *siteRT {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if s, ok := pr.exact[host]; ok {
		return s
	}
	for _, w := range pr.wild {
		if strings.HasSuffix(host, w.suffix) {
			return w.site
		}
	}
	return pr.any
}

func contains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// redirectHost keeps the requested host only when it is one of the site's
// names, so a forged Host header cannot turn the redirect into another site.
func redirectHost(s *siteRT, host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	fallback := ""
	for _, n := range s.site.ServerNames {
		n = strings.ToLower(n)
		switch {
		case n == "_":
			continue
		case strings.HasPrefix(n, "*."):
			if strings.HasSuffix(host, n[1:]) && validHost(host) {
				return host
			}
		case n == host:
			return host
		case fallback == "":
			fallback = n
		}
	}
	if fallback != "" || !validHost(host) {
		return fallback
	}
	return host
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// canonicalPath rejects dot segments, empty segments and backslashes.
func canonicalPath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return p == "" || p == "*"
	}
	if strings.ContainsRune(p, '\\') {
		return false
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c == p
}

// clientIP returns the visitor address, honouring X-Forwarded-For only when
// the direct peer is a trusted proxy (e.g. a load balancer in front).
func (e *Engine) clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || !contains(e.opt.TrustedProxies, ip) {
		return ip
	}
	// A client can send its own X-Forwarded-For line before the one the
	// proxy adds, so every line is taken into account.
	xff := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	parts := strings.Split(xff, ",")
	// Walk from the right, skipping our own trusted hops.
	for i := len(parts) - 1; i >= 0; i-- {
		c := net.ParseIP(strings.TrimSpace(parts[i]))
		if c == nil {
			break
		}
		if !contains(e.opt.TrustedProxies, c) {
			return c
		}
		ip = c
	}
	return ip
}

// reqInfo collects what the access log needs while a request is served.
type reqInfo struct {
	site   int
	ip     net.IP
	action string
	event  string
}

type infoKey struct{}

func infoOf(r *http.Request) *reqInfo {
	i, _ := r.Context().Value(infoKey{}).(*reqInfo)
	return i
}

func (i *reqInfo) set(action string) {
	if i != nil {
		i.action = action
	}
}

// statusWriter records the status and size of a response. Unwrap lets
// http.ResponseController reach Flush and Hijack (streaming, WebSockets).
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (e *Engine) handler(port int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e.opt.Access == nil {
			e.serve(port, w, r, nil)
			return
		}
		start := time.Now()
		info := &reqInfo{action: "proxied"}
		sw := &statusWriter{ResponseWriter: w}
		r = r.WithContext(context.WithValue(r.Context(), infoKey{}, info))
		e.serve(port, sw, r, info)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		ip := info.ip
		if ip == nil {
			ip = e.clientIP(r)
		}
		ipStr := ""
		if ip != nil {
			ipStr = ip.String()
		}
		e.opt.Access.Log(accesslog.Entry{
			Time: start.UTC(), SiteID: info.site, Host: r.Host, ClientIP: ipStr, Country: e.country(ip),
			Method: r.Method, URI: r.URL.RequestURI(), Proto: r.Proto, TLS: r.TLS != nil || e.portTLS(port),
			Status: sw.status, Bytes: sw.bytes, DurationMS: float64(time.Since(start).Microseconds()) / 1000,
			UserAgent: r.UserAgent(), Referer: r.Referer(), Action: info.action, EventID: info.event,
		})
	})
}

func (e *Engine) portTLS(port int) bool {
	pr := e.rt.Load().ports[port]
	return pr != nil && pr.tls
}

func (e *Engine) serve(port int, w http.ResponseWriter, r *http.Request, info *reqInfo) {
	pr := e.rt.Load().ports[port]
	if pr == nil {
		info.set("error")
		http.Error(w, "no site", http.StatusMisdirectedRequest)
		return
	}
	if !pr.tls && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		if cp := e.certProvider(); cp != nil {
			info.set("acme")
			cp.HTTPHandler(http.NotFoundHandler()).ServeHTTP(w, r)
			return
		}
	}
	s := pr.route(r.Host)
	if s == nil {
		info.set("error")
		http.Error(w, "unknown site", http.StatusNotFound)
		return
	}
	if info != nil {
		info.site = s.site.ID
	}
	e.serveSite(w, r, s, pr.tls)
}

func (e *Engine) country(ip net.IP) string {
	if e.opt.GeoIP == nil {
		return ""
	}
	return e.opt.GeoIP.Country(ip)
}

func (e *Engine) event(r *http.Request, s *siteRT, ip net.IP, kind, action string, status int) events.Event {
	return events.Event{
		ID: events.NewID(), Time: time.Now().UTC(), SiteID: s.site.ID, Host: r.Host,
		ClientIP: ip.String(), Country: e.country(ip), Method: r.Method, URI: r.URL.RequestURI(), UA: r.UserAgent(),
		Kind: kind, Action: action, Status: status,
	}
}

func hasCode(list []string, c string) bool {
	for _, x := range list {
		if x == c {
			return true
		}
	}
	return false
}

func (e *Engine) block(w http.ResponseWriter, r *http.Request, ev events.Event) {
	if i := infoOf(r); i != nil {
		i.action, i.event = "blocked", ev.ID
	}
	e.opt.Events.Add(ev)
	writeBlock(w, e.opt.Brand, ev.Status, ev.ID)
}

func (e *Engine) serveSite(w http.ResponseWriter, r *http.Request, s *siteRT, isTLS bool) {
	ip := e.clientIP(r)
	if ip == nil {
		ip = net.IPv4zero
	}
	if i := infoOf(r); i != nil {
		i.ip = ip
	}
	e.opt.Events.CountRequest(s.site.ID)

	// Rules match on the path as sent, and most upstreams resolve dot
	// segments themselves: "/static/../admin" must not pass as "/static/".
	if !canonicalPath(r.URL.Path) {
		e.block(w, r, e.event(r, s, ip, "bad_path", "block", http.StatusBadRequest))
		return
	}

	if s.site.RedirectHTTPS && !isTLS && s.httpsPort != 0 {
		host := redirectHost(s, r.Host)
		if host == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if s.httpsPort != 443 {
			host = net.JoinHostPort(host, strconv.Itoa(s.httpsPort))
		} else if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		infoOf(r).set("redirected")
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}

	if contains(s.deny, ip) {
		e.block(w, r, e.event(r, s, ip, "ip_deny", "block", http.StatusForbidden))
		return
	}
	if len(s.allow) > 0 && !contains(s.allow, ip) {
		e.block(w, r, e.event(r, s, ip, "ip_allow", "block", http.StatusForbidden))
		return
	}
	if len(s.site.CountryAllow) > 0 || len(s.site.CountryDeny) > 0 {
		c := e.country(ip)
		// Unknown countries (private ranges, no database) are not blocked by
		// a deny list, but are refused by an allow list.
		if (c != "" && hasCode(s.site.CountryDeny, c)) || (len(s.site.CountryAllow) > 0 && !hasCode(s.site.CountryAllow, c)) {
			e.block(w, r, e.event(r, s, ip, "geo", "block", http.StatusForbidden))
			return
		}
	}
	// Path rules: deny and allow stop the evaluation.
	allowed, skipWAF := false, false
rules:
	for i := range s.rules {
		rule := &s.rules[i]
		if !rule.matches(r, ip) {
			continue
		}
		switch rule.Action {
		case model.RuleDeny:
			e.block(w, r, e.event(r, s, ip, "rule", "block", http.StatusForbidden))
			return
		case model.RuleAllow:
			allowed = true
			break rules
		case model.RuleSkipWAF:
			skipWAF = true
		case model.RuleRateLimit:
			rl := rule.RateLimit
			key := strconv.Itoa(s.site.ID) + "|r" + strconv.Itoa(i) + "|" + ipKey(ip)
			if !e.limiter.allow(key, rl.Requests, time.Duration(rl.WindowSec)*time.Second, time.Duration(rl.BlockSec)*time.Second, time.Now()) {
				e.block(w, r, e.event(r, s, ip, "rate_limit", "block", http.StatusTooManyRequests))
				return
			}
		}
	}

	if rl := s.site.RateLimit; rl.Requests > 0 && !allowed {
		key := strconv.Itoa(s.site.ID) + "|" + ipKey(ip)
		if !e.limiter.allow(key, rl.Requests, time.Duration(rl.WindowSec)*time.Second, time.Duration(rl.BlockSec)*time.Second, time.Now()) {
			e.block(w, r, e.event(r, s, ip, "rate_limit", "block", http.StatusTooManyRequests))
			return
		}
	}

	if e.handleEngineEndpoint(w, r, s, ip, isTLS) {
		return
	}
	if !allowed && !e.challenges(w, r, s, ip) {
		return
	}

	if s.waf != nil && !allowed && !skipWAF {
		tx := s.waf.NewTransaction()
		defer func() {
			tx.ProcessLogging()
			_ = tx.Close()
		}()
		it, err := inspect(tx, r, ip)
		if err != nil {
			e.opt.Log.Warn("waf inspection failed", "site", s.site.ID, "err", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if it != nil {
			status := it.Status
			if status < 400 || status > 599 {
				status = http.StatusForbidden
			}
			ev := e.event(r, s, ip, "waf", "block", status)
			ev.Rules, ev.Tags = matched(tx)
			e.block(w, r, ev)
			return
		}
		if s.site.Mode == model.ModeMonitor {
			if rules, tags := matched(tx); anomalyExceeded(tx) {
				ev := e.event(r, s, ip, "waf", "monitor", 0)
				ev.Rules, ev.Tags = rules, tags
				e.opt.Events.Add(ev)
			}
		}
	}

	up := s.pick()
	if up == nil {
		http.Error(w, "no upstream available", http.StatusBadGateway)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, ctxVal{ip: ip, tls: isTLS}))
	up.proxy.ServeHTTP(w, r)
}

// inspect runs Coraza phases 0–2. It mirrors coraza/http.processRequest but
// uses the resolved client address.
func inspect(tx types.Transaction, r *http.Request, ip net.IP) (*types.Interruption, error) {
	_, portStr, _ := net.SplitHostPort(r.RemoteAddr)
	port, _ := strconv.Atoi(portStr)
	tx.ProcessConnection(ip.String(), port, "", 0)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}
	if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		it, _, err := tx.ReadRequestBodyFrom(r.Body)
		if err != nil {
			return nil, err
		}
		if it != nil {
			return it, nil
		}
		rbr, err := tx.RequestBodyReader()
		if err != nil {
			return nil, err
		}
		r.Body = readCloser{Reader: ioMulti(rbr, r.Body), c: r.Body}
	}
	return tx.ProcessRequestBody()
}

// anomaly evaluation rule of CRS
const ruleInboundAnomaly = 949110

func anomalyExceeded(tx types.Transaction) bool {
	for _, m := range tx.MatchedRules() {
		if m.Rule().ID() == ruleInboundAnomaly {
			return true
		}
	}
	return false
}

func matched(tx types.Transaction) ([]events.Rule, []string) {
	var out []events.Rule
	tagSet := map[string]bool{}
	for _, m := range tx.MatchedRules() {
		rule := m.Rule()
		// 900000-909999 are CRS initialisation/bookkeeping rules, not findings.
		if m.Message() == "" || (rule.ID() >= 900000 && rule.ID() < 910000) {
			continue
		}
		out = append(out, events.Rule{ID: rule.ID(), Msg: m.Message(), Data: truncate(m.Data(), 200), Severity: rule.Severity().String()})
		for _, t := range rule.Tags() {
			if strings.HasPrefix(t, "attack-") {
				tagSet[t] = true
			}
		}
		if len(out) >= 20 {
			break
		}
	}
	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return out, tags
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
