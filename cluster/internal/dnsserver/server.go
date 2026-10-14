// Package dnsserver is an authoritative DNS server that answers the records
// of protected domains with the healthy WAF nodes of a pool. It is how
// traffic is spread across, and failed over between, cluster nodes.
package dnsserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
)

type regionRule struct {
	net    *net.IPNet
	region string
}

type record struct {
	config.Record
	fqdn  string
	rules []regionRule
	rr    dns.RR // static records
}

type zone struct {
	config.Zone
	origin  string
	records map[string][]*record // by lower-case FQDN
}

// Server is the DNS server.
type Server struct {
	cfg   *config.DNS
	log   *slog.Logger
	zones []*zone
	http  *http.Client
	base  *url.URL

	mu    sync.RWMutex
	pools map[string][]api.Endpoint

	// rnd is replaceable in tests.
	rnd func(n int) int
}

// New validates zones and builds the server.
func New(cfg *config.DNS, log *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, log: log, pools: map[string][]api.Endpoint{}, rnd: rand.IntN}
	for _, zc := range cfg.Zones {
		z := &zone{Zone: zc, origin: dns.Fqdn(strings.ToLower(zc.Name)), records: map[string][]*record{}}
		for i := range z.NS {
			z.NS[i] = dns.Fqdn(z.NS[i])
		}
		z.Hostmaster = dns.Fqdn(z.Hostmaster)
		for _, rc := range zc.Records {
			r := &record{Record: rc}
			r.Type = strings.ToUpper(r.Type)
			if r.Name == "" || r.Name == "@" {
				r.fqdn = z.origin
			} else {
				r.fqdn = dns.Fqdn(strings.ToLower(r.Name) + "." + z.origin)
			}
			if r.TTL == 0 {
				r.TTL = z.TTL
			}
			if r.Pool != "" {
				if r.Type == "" {
					r.Type = "A"
				}
				if r.Type != "A" && r.Type != "AAAA" {
					return nil, fmt.Errorf("zone %s record %s: pool records must be A or AAAA", zc.Name, rc.Name)
				}
				for _, pr := range r.PreferRegion {
					_, n, err := net.ParseCIDR(pr.CIDR)
					if err != nil {
						return nil, fmt.Errorf("zone %s record %s: %w", zc.Name, rc.Name, err)
					}
					r.rules = append(r.rules, regionRule{n, pr.Region})
				}
			} else {
				rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", r.fqdn, r.TTL, r.Type, r.Value))
				if err != nil || rr == nil {
					return nil, fmt.Errorf("zone %s record %s %s: invalid static record: %v", zc.Name, rc.Name, rc.Type, err)
				}
				r.rr = rr
			}
			z.records[r.fqdn] = append(z.records[r.fqdn], r)
		}
		s.zones = append(s.zones, z)
	}
	// Longest origin first so sub-zones win.
	sort.Slice(s.zones, func(i, j int) bool { return len(s.zones[i].origin) > len(s.zones[j].origin) })

	u, err := url.Parse(strings.TrimRight(cfg.ControllerURL, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid controller_url %q", cfg.ControllerURL)
	}
	if u.Scheme != "https" {
		if ip := net.ParseIP(u.Hostname()); u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("controller_url must use https unless it is a loopback address (the DNS token would travel in clear)")
		}
	}
	s.base = u
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.ControllerCA != "" {
		pem, err := os.ReadFile(cfg.ControllerCA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s has no PEM certificate", cfg.ControllerCA)
		}
		tlsCfg.RootCAs = pool
	}
	s.http = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	return s, nil
}

// SetPool replaces the endpoints of a pool (used by refresh and tests).
func (s *Server) SetPool(pool string, eps []api.Endpoint) {
	s.mu.Lock()
	s.pools[pool] = eps
	s.mu.Unlock()
}

func (s *Server) poolNames() []string {
	seen := map[string]bool{}
	for _, z := range s.zones {
		for _, rs := range z.records {
			for _, r := range rs {
				if r.Pool != "" {
					seen[r.Pool] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Refresh fetches every pool from the controller. A pool that cannot be
// fetched keeps its last known endpoints so DNS keeps answering while the
// controller is unreachable.
func (s *Server) Refresh(ctx context.Context) {
	for _, p := range s.poolNames() {
		var pe api.PoolEndpoints
		if err := s.get(ctx, "/v1/pools/"+url.PathEscape(p)+"/endpoints", &pe); err != nil {
			s.log.Warn("refresh pool failed, keeping last known endpoints", "pool", p, "err", err)
			continue
		}
		s.SetPool(p, pe.Endpoints)
	}
}

func (s *Server) get(ctx context.Context, path string, out any) error {
	u := *s.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.Unmarshal(b, out)
}

// Run serves UDP and TCP until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	s.Refresh(ctx)
	go func() {
		t := time.NewTicker(s.cfg.Refresh.Duration)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.Refresh(ctx)
			}
		}
	}()
	errc := make(chan error, 2)
	servers := []*dns.Server{
		{Addr: s.cfg.Listen, Net: "udp", Handler: s},
		{Addr: s.cfg.Listen, Net: "tcp", Handler: s, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second},
	}
	for _, srv := range servers {
		go func(srv *dns.Server) { errc <- srv.ListenAndServe() }(srv)
	}
	s.log.Info("dns listening", "addr", s.cfg.Listen, "zones", len(s.zones))
	select {
	case <-ctx.Done():
		for _, srv := range servers {
			_ = srv.Shutdown()
		}
		return nil
	case err := <-errc:
		return err
	}
}

func (s *Server) findZone(name string) *zone {
	for _, z := range s.zones {
		if dns.IsSubDomain(z.origin, name) {
			return z
		}
	}
	return nil
}

func (z *zone) soa() dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: z.origin, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: z.TTL},
		Ns:      z.NS[0],
		Mbox:    z.Hostmaster,
		Serial:  z.Serial,
		Refresh: 3600, Retry: 600, Expire: 604800,
		Minttl: z.TTL,
	}
}

func (z *zone) nsRRs() []dns.RR {
	out := make([]dns.RR, 0, len(z.NS))
	for _, n := range z.NS {
		out = append(out, &dns.NS{Hdr: dns.RR_Header{Name: z.origin, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: z.TTL}, Ns: n})
	}
	return out
}

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := s.answer(req, clientIP(w.RemoteAddr()))
	_ = w.WriteMsg(m)
}

func clientIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	}
	return nil
}

func (s *Server) answer(req *dns.Msg, remote net.IP) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Compress = true
	if len(req.Question) != 1 || req.Opcode != dns.OpcodeQuery {
		m.SetRcode(req, dns.RcodeNotImplemented)
		return m
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	z := s.findZone(name)
	if z == nil {
		m.SetRcode(req, dns.RcodeRefused)
		return m
	}
	m.Authoritative = true

	client := remote
	var ecs *dns.EDNS0_SUBNET
	if opt := req.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if e, ok := o.(*dns.EDNS0_SUBNET); ok {
				ecs = e
				client = e.Address
			}
		}
		resp := new(dns.OPT)
		resp.Hdr.Name, resp.Hdr.Rrtype = ".", dns.TypeOPT
		resp.SetUDPSize(1232)
		if ecs != nil {
			echo := *ecs
			echo.SourceScope = ecs.SourceNetmask
			resp.Option = append(resp.Option, &echo)
		}
		defer func() { m.Extra = append(m.Extra, resp) }()
	}

	if name == z.origin {
		switch q.Qtype {
		case dns.TypeSOA:
			m.Answer = append(m.Answer, z.soa())
			return m
		case dns.TypeNS:
			m.Answer = append(m.Answer, z.nsRRs()...)
			return m
		}
	}

	recs := z.records[name]
	if len(recs) == 0 && name != z.origin {
		m.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, z.soa())
		return m
	}

	for _, r := range recs {
		if r.rr != nil {
			t := r.rr.Header().Rrtype
			if t == q.Qtype || q.Qtype == dns.TypeANY || (t == dns.TypeCNAME && q.Qtype != dns.TypeCNAME) {
				m.Answer = append(m.Answer, dns.Copy(r.rr))
			}
			continue
		}
		// A dynamic record of type A hands out IPv4, one of type AAAA IPv6.
		anyQ := q.Qtype == dns.TypeANY
		wantA := r.Type == "A" && (q.Qtype == dns.TypeA || anyQ)
		wantAAAA := r.Type == "AAAA" && (q.Qtype == dns.TypeAAAA || anyQ)
		if !wantA && !wantAAAA {
			continue
		}
		for _, ep := range s.pick(r, client) {
			if wantA && ep.IPv4 != "" {
				if ip := net.ParseIP(ep.IPv4).To4(); ip != nil {
					m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: r.TTL}, A: ip})
				}
			}
			if wantAAAA && ep.IPv6 != "" {
				if ip := net.ParseIP(ep.IPv6); ip != nil && ip.To4() == nil {
					m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: r.TTL}, AAAA: ip})
				}
			}
		}
	}
	// A CNAME owner must not carry other data; if we answered a CNAME drop
	// anything else.
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == dns.TypeCNAME && q.Qtype != dns.TypeCNAME {
			m.Answer = []dns.RR{rr}
			break
		}
	}
	if len(m.Answer) == 0 {
		m.Ns = append(m.Ns, z.soa()) // NODATA
	}
	return m
}

// pick chooses the endpoints of a dynamic record for a client.
func (s *Server) pick(r *record, client net.IP) []api.Endpoint {
	s.mu.RLock()
	all := s.pools[r.Pool]
	s.mu.RUnlock()

	healthy := make([]api.Endpoint, 0, len(all))
	for _, e := range all {
		if e.Healthy {
			healthy = append(healthy, e)
		}
	}
	if len(healthy) == 0 {
		if !r.FailOpen {
			return nil
		}
		healthy = append(healthy, all...)
	}

	// Region preference: keep the client's region when it has a healthy node.
	if client != nil {
		for _, rule := range r.rules {
			if !rule.net.Contains(client) {
				continue
			}
			var local []api.Endpoint
			for _, e := range healthy {
				if e.Region == rule.region {
					local = append(local, e)
				}
			}
			if len(local) > 0 {
				healthy = local
			}
			break
		}
	}

	n := r.MaxAnswers
	if n <= 0 || n > len(healthy) {
		n = len(healthy)
	}
	return s.weightedSample(healthy, n)
}

// weightedSample draws n endpoints without replacement, proportionally to
// their weight, so heavier nodes are listed first more often.
func (s *Server) weightedSample(in []api.Endpoint, n int) []api.Endpoint {
	pool := append([]api.Endpoint(nil), in...)
	out := make([]api.Endpoint, 0, n)
	for len(out) < n && len(pool) > 0 {
		total := 0
		for _, e := range pool {
			total += max(e.Weight, 1)
		}
		x := s.rnd(total)
		i := 0
		for ; i < len(pool); i++ {
			x -= max(pool[i].Weight, 1)
			if x < 0 {
				break
			}
		}
		out = append(out, pool[i])
		pool = append(pool[:i], pool[i+1:]...)
	}
	return out
}
