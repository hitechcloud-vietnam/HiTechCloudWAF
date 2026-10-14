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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

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
	Log    *slog.Logger
	Events *events.Log
}

type upstream struct {
	url       *url.URL
	proxy     *httputil.ReverseProxy
	downUntil atomic.Int64
}

type siteRT struct {
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

// Engine serves all sites.
type Engine struct {
	opt     Options
	pool    *WAFPool
	limiter *limiter
	rt      atomic.Pointer[runtime]

	mu        sync.Mutex
	listeners map[int]*listener
	ctx       context.Context
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
			if isTLS {
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
				GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) { return e.certFor(p, h.ServerName) },
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

func (e *Engine) certFor(port int, sni string) (*tls.Certificate, error) {
	pr := e.rt.Load().ports[port]
	if pr == nil {
		return nil, errors.New("no site on this port")
	}
	sni = strings.ToLower(sni)
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
	xff := r.Header.Get("X-Forwarded-For")
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

func (e *Engine) handler(port int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pr := e.rt.Load().ports[port]
		if pr == nil {
			http.Error(w, "no site", http.StatusMisdirectedRequest)
			return
		}
		s := pr.route(r.Host)
		if s == nil {
			http.Error(w, "unknown site", http.StatusNotFound)
			return
		}
		e.serveSite(w, r, s, pr.tls)
	})
}

func (e *Engine) event(r *http.Request, s *siteRT, ip net.IP, kind, action string, status int) events.Event {
	return events.Event{
		ID: events.NewID(), Time: time.Now().UTC(), SiteID: s.site.ID, Host: r.Host,
		ClientIP: ip.String(), Method: r.Method, URI: r.URL.RequestURI(), UA: r.UserAgent(),
		Kind: kind, Action: action, Status: status,
	}
}

func (e *Engine) block(w http.ResponseWriter, ev events.Event) {
	e.opt.Events.Add(ev)
	writeBlock(w, e.opt.Brand, ev.Status, ev.ID)
}

func (e *Engine) serveSite(w http.ResponseWriter, r *http.Request, s *siteRT, isTLS bool) {
	ip := e.clientIP(r)
	if ip == nil {
		ip = net.IPv4zero
	}
	e.opt.Events.CountRequest(s.site.ID)

	if s.site.RedirectHTTPS && !isTLS && s.httpsPort != 0 {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if s.httpsPort != 443 {
			host = net.JoinHostPort(host, strconv.Itoa(s.httpsPort))
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}

	if contains(s.deny, ip) {
		e.block(w, e.event(r, s, ip, "ip_deny", "block", http.StatusForbidden))
		return
	}
	if len(s.allow) > 0 && !contains(s.allow, ip) {
		e.block(w, e.event(r, s, ip, "ip_allow", "block", http.StatusForbidden))
		return
	}
	if rl := s.site.RateLimit; rl.Requests > 0 {
		key := strconv.Itoa(s.site.ID) + "|" + ip.String()
		if !e.limiter.allow(key, rl.Requests, time.Duration(rl.WindowSec)*time.Second, time.Duration(rl.BlockSec)*time.Second, time.Now()) {
			e.block(w, e.event(r, s, ip, "rate_limit", "block", http.StatusTooManyRequests))
			return
		}
	}

	if e.handleEngineEndpoint(w, r, s, ip, isTLS) {
		return
	}
	if !e.challenges(w, r, s, ip) {
		return
	}

	if s.waf != nil {
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
			e.block(w, ev)
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
		// 90xxxx are CRS initialisation/bookkeeping rules, not findings.
		if m.Message() == "" || rule.ID() < 910000 {
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
