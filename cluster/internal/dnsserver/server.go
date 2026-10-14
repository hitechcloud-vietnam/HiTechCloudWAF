// Package dnsserver is an authoritative DNS server that answers the records
// of protected domains with the healthy WAF nodes of a pool. It is how
// traffic is spread across, and failed over between, cluster nodes. Zones
// also carry static records, from the configuration file and from the
// controller API.
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
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/dnsrecord"
)

// maxCNAMEChain bounds how many in-zone CNAMEs one answer follows.
const maxCNAMEChain = 8

var errNotModified = errors.New("not modified")

type regionRule struct {
	net    *net.IPNet
	region string
}

type record struct {
	config.Record
	fqdn    string
	rules   []regionRule
	country []countryRule
	rr      dns.RR // static records
}

func (r *record) isCNAME() bool { return r.rr != nil && r.rr.Header().Rrtype == dns.TypeCNAME }

type zone struct {
	config.Zone
	origin string
	local  []*record // records of the configuration file
}

// zoneData is what a zone answers from: its local records merged with the
// static records of the controller. It is rebuilt, never modified.
type zoneData struct {
	origin  string
	records map[string][]*record // by lower-case FQDN
	names   map[string]bool      // owners and their ancestors (empty non-terminals)
	cuts    map[string]bool      // delegation points (NS records below the apex)
	serial  uint32
}

func newZoneData(origin string, serial uint32) *zoneData {
	return &zoneData{origin: origin, records: map[string][]*record{}, names: map[string]bool{origin: true}, cuts: map[string]bool{}, serial: serial}
}

// add inserts r, refusing a CNAME next to other data and duplicates.
func (d *zoneData) add(r *record) error {
	for _, o := range d.records[r.fqdn] {
		if o.isCNAME() || r.isCNAME() {
			return fmt.Errorf("%s: a CNAME cannot coexist with other data", r.fqdn)
		}
		if o.rr != nil && r.rr != nil && dns.IsDuplicate(o.rr, r.rr) {
			return fmt.Errorf("duplicate record %s", strings.Join(strings.Fields(r.rr.String()), " "))
		}
	}
	d.records[r.fqdn] = append(d.records[r.fqdn], r)
	for n := r.fqdn; n != d.origin && n != "."; n = parent(n) {
		d.names[n] = true
	}
	if r.rr != nil && r.rr.Header().Rrtype == dns.TypeNS && r.fqdn != d.origin {
		d.cuts[r.fqdn] = true
	}
	return nil
}

func parent(name string) string {
	i, end := dns.NextLabel(name, 0)
	if end {
		return "."
	}
	return name[i:]
}

// lookup finds the records of name: an exact match, an empty non-terminal
// (exists, no records) or the wildcard of the closest encloser (RFC 4592).
func (d *zoneData) lookup(name string) ([]*record, bool) {
	if rs, ok := d.records[name]; ok {
		return rs, true
	}
	if d.names[name] {
		return nil, true
	}
	for p := parent(name); p != "."; p = parent(p) {
		if d.names[p] {
			rs, ok := d.records["*."+p]
			return rs, ok
		}
	}
	return nil, false
}

// cutFor returns the topmost delegation point at or above name, if any.
func (d *zoneData) cutFor(name string) string {
	if len(d.cuts) == 0 {
		return ""
	}
	cut := ""
	for n := name; n != d.origin && n != "."; n = parent(n) {
		if d.cuts[n] {
			cut = n
		}
	}
	return cut
}

// Server is the DNS server.
type Server struct {
	cfg   *config.DNS
	log   *slog.Logger
	zones []*zone
	http  *http.Client
	base  *url.URL
	geo   *geoDB

	mu    sync.RWMutex
	pools map[string][]api.Endpoint
	data  map[*zone]*zoneData
	// etag of the controller's static record set last applied.
	recordsETag string

	// rnd is replaceable in tests.
	rnd func(n int) int
}

// New validates zones and builds the server.
func New(cfg *config.DNS, log *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, log: log, pools: map[string][]api.Endpoint{}, rnd: rand.IntN}
	if cfg.GeoIPDB != "" {
		g, err := openGeoDB(cfg.GeoIPDB)
		if err != nil {
			return nil, fmt.Errorf("geoip_db: %w", err)
		}
		s.geo = g
	}
	for name, p := range cfg.Pools {
		if _, err := compileCountryRules(p.PreferCountry); err != nil {
			return nil, fmt.Errorf("dns pool %s: %w", name, err)
		}
	}
	for _, zc := range cfg.Zones {
		z := &zone{Zone: zc, origin: dnsrecord.Origin(zc.Name)}
		if _, ok := dns.IsDomainName(z.origin); !ok {
			return nil, fmt.Errorf("invalid zone name %q", zc.Name)
		}
		z.NS = make([]string, len(zc.NS))
		for i, n := range zc.NS {
			z.NS[i] = dns.Fqdn(strings.ToLower(n))
		}
		z.Hostmaster = dns.Fqdn(z.Hostmaster)
		check := newZoneData(z.origin, 0)
		for _, rc := range zc.Records {
			r, err := s.compile(z, rc)
			if err != nil {
				return nil, fmt.Errorf("zone %s record %s %s: %w", zc.Name, rc.Name, rc.Type, err)
			}
			if err := check.add(r); err != nil {
				return nil, fmt.Errorf("zone %s: %w", zc.Name, err)
			}
			z.local = append(z.local, r)
		}
		s.zones = append(s.zones, z)
	}
	// Longest origin first so sub-zones win.
	sort.Slice(s.zones, func(i, j int) bool { return len(s.zones[i].origin) > len(s.zones[j].origin) })
	s.rebuild(api.DNSRecordSet{})

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

// compile validates one record of the configuration file.
func (s *Server) compile(z *zone, rc config.Record) (*record, error) {
	r := &record{Record: rc}
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	if r.TTL == 0 {
		r.TTL = z.TTL
	}
	if r.Pool == "" {
		rr, err := dnsrecord.Build(z.origin, rc.Name, r.Type, rc.Value, r.TTL)
		if err != nil {
			return nil, err
		}
		r.fqdn, r.rr = rr.Header().Name, rr
		return r, nil
	}
	fqdn, err := dnsrecord.Owner(z.origin, rc.Name)
	if err != nil {
		return nil, err
	}
	r.fqdn = fqdn
	if r.Type == "" {
		r.Type = "A"
	}
	if r.Type != "A" && r.Type != "AAAA" {
		return nil, errors.New("pool records must be A or AAAA")
	}
	for _, pr := range r.PreferRegion {
		_, n, err := net.ParseCIDR(pr.CIDR)
		if err != nil {
			return nil, err
		}
		r.rules = append(r.rules, regionRule{n, pr.Region})
	}
	countries := rc.PreferCountry
	if len(countries) == 0 {
		countries = s.cfg.Pools[r.Pool].PreferCountry
	}
	if r.country, err = compileCountryRules(countries); err != nil {
		return nil, err
	}
	if len(r.country) > 0 && s.geo == nil {
		s.log.Warn("prefer_country needs dns.geoip_db; country routing disabled", "zone", z.Name, "record", rc.Name)
	}
	return r, nil
}

// rebuild merges the local records with the controller's static records.
// A controller record that is invalid or conflicts with a local one is
// skipped: the configuration file wins.
func (s *Server) rebuild(set api.DNSRecordSet) {
	data := make(map[*zone]*zoneData, len(s.zones))
	byOrigin := make(map[string]*zone, len(s.zones))
	for _, z := range s.zones {
		d := newZoneData(z.origin, max(z.Serial, set.Serial))
		for _, r := range z.local {
			_ = d.add(r) // validated by New
		}
		data[z], byOrigin[z.origin] = d, z
	}
	for _, rc := range set.Records {
		z := byOrigin[dnsrecord.Origin(rc.Zone)]
		if z == nil {
			continue // a zone served by other DNS servers
		}
		ttl := rc.TTL
		if ttl == 0 {
			ttl = z.TTL
		}
		rr, err := dnsrecord.Build(z.origin, rc.Name, rc.Type, rc.Value, ttl)
		if err == nil {
			r := &record{Record: config.Record{Name: rc.Name, Type: strings.ToUpper(rc.Type), Value: rc.Value, TTL: ttl}, fqdn: rr.Header().Name, rr: rr}
			err = data[z].add(r)
		}
		if err != nil {
			s.log.Warn("controller dns record ignored", "id", rc.ID, "zone", rc.Zone, "name", rc.Name, "type", rc.Type, "err", err)
		}
	}
	s.mu.Lock()
	s.data = data
	s.mu.Unlock()
}

// SetPool replaces the endpoints of a pool (used by refresh and tests).
func (s *Server) SetPool(pool string, eps []api.Endpoint) {
	s.mu.Lock()
	s.pools[pool] = eps
	s.mu.Unlock()
}

// SetRecords replaces the controller's static records (used by refresh and
// tests).
func (s *Server) SetRecords(set api.DNSRecordSet) { s.rebuild(set) }

func (s *Server) poolNames() []string {
	seen := map[string]bool{}
	for _, z := range s.zones {
		for _, r := range z.local {
			if r.Pool != "" {
				seen[r.Pool] = true
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

// Refresh fetches every pool and the static records from the controller.
// Data that cannot be fetched keeps its last known value so DNS keeps
// answering while the controller is unreachable. It also reloads the GeoIP
// database when its file changed.
func (s *Server) Refresh(ctx context.Context) {
	for _, p := range s.poolNames() {
		var pe api.PoolEndpoints
		if err := s.get(ctx, "/v1/pools/"+url.PathEscape(p)+"/endpoints", nil, &pe); err != nil {
			s.log.Warn("refresh pool failed, keeping last known endpoints", "pool", p, "err", err)
			continue
		}
		s.SetPool(p, pe.Endpoints)
	}

	s.mu.RLock()
	etag := s.recordsETag
	s.mu.RUnlock()
	var set api.DNSRecordSet
	switch err := s.get(ctx, "/v1/dns/records", &etag, &set); {
	case errors.Is(err, errNotModified):
	case err != nil:
		s.log.Warn("refresh dns records failed, keeping last known records", "err", err)
	default:
		s.rebuild(set)
		s.mu.Lock()
		s.recordsETag = etag
		s.mu.Unlock()
		s.log.Debug("dns records updated", "serial", set.Serial, "records", len(set.Records))
	}

	if s.geo != nil {
		if changed, err := s.geo.reloadIfChanged(); err != nil {
			s.log.Warn("reload geoip_db failed, keeping the loaded database", "err", err)
		} else if changed {
			s.log.Info("geoip_db reloaded", "path", s.cfg.GeoIPDB)
		}
	}
}

// get fetches path into out. When etag is not nil it is sent as
// If-None-Match and updated from the response; errNotModified reports a 304.
func (s *Server) get(ctx context.Context, path string, etag *string, out any) error {
	u := *s.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	if etag != nil && *etag != "" {
		req.Header.Set("If-None-Match", *etag)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusNotModified && etag != nil {
		return errNotModified
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if err := json.Unmarshal(b, out); err != nil {
		return err
	}
	if etag != nil {
		*etag = resp.Header.Get("ETag")
	}
	return nil
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
	s.log.Info("dns listening", "addr", s.cfg.Listen, "zones", len(s.zones), "geoip", s.geo != nil)
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

func (z *zone) soa(serial uint32) dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: z.origin, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: z.TTL},
		Ns:      z.NS[0],
		Mbox:    z.Hostmaster,
		Serial:  serial,
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

func (z *zone) hasNS(target string) bool {
	for _, n := range z.NS {
		if strings.EqualFold(n, target) {
			return true
		}
	}
	return false
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
	z := s.findZone(strings.ToLower(q.Name))
	if z == nil {
		m.SetRcode(req, dns.RcodeRefused)
		return m
	}
	m.Authoritative = true

	client := remote
	var ecs *dns.EDNS0_SUBNET
	var opt *dns.OPT
	if o := req.IsEdns0(); o != nil {
		for _, op := range o.Option {
			if e, ok := op.(*dns.EDNS0_SUBNET); ok {
				ecs = e
				client = e.Address
			}
		}
		opt = new(dns.OPT)
		opt.Hdr.Name, opt.Hdr.Rrtype = ".", dns.TypeOPT
		opt.SetUDPSize(1232)
	}

	usedClient := s.resolve(m, z, q, client)

	if opt != nil {
		if ecs != nil {
			// Scope 0 tells resolvers the answer is valid for every client;
			// only answers routed by client address are scoped to its subnet.
			echo := *ecs
			echo.SourceScope = 0
			if usedClient {
				echo.SourceScope = ecs.SourceNetmask
			}
			opt.Option = append(opt.Option, &echo)
		}
		m.Extra = append(m.Extra, opt)
	}
	return m
}

// resolve fills m with the answer to q in z, following CNAMEs into the zones
// this server is authoritative for. It reports whether the answer depends on
// the client address.
func (s *Server) resolve(m *dns.Msg, z *zone, q dns.Question, client net.IP) bool {
	s.mu.RLock()
	data := s.data
	s.mu.RUnlock()

	usedClient := false
	name := q.Name
	seen := map[string]bool{}
	for hop := 0; ; hop++ {
		d := data[z]
		lname := strings.ToLower(name)
		seen[lname] = true

		// Below a delegation: refer to the child zone's name servers. A DS
		// query at the cut belongs to this (parent) zone.
		if cut := d.cutFor(lname); cut != "" && (cut != lname || q.Qtype != dns.TypeDS) {
			if hop == 0 {
				m.Authoritative = false
			}
			s.referral(m, d, cut)
			return usedClient
		}

		recs, ok := d.lookup(lname)
		if !ok {
			m.Rcode = dns.RcodeNameError
			m.Ns = append(m.Ns, z.soa(d.serial))
			return usedClient
		}
		if len(recs) == 1 && recs[0].isCNAME() && q.Qtype != dns.TypeCNAME {
			rr := dns.Copy(recs[0].rr)
			rr.Header().Name = name
			m.Answer = append(m.Answer, rr)
			target := rr.(*dns.CNAME).Target
			lt := strings.ToLower(target)
			nz := s.findZone(lt)
			if nz == nil || seen[lt] || hop+1 >= maxCNAMEChain {
				return usedClient // the resolver follows the chain
			}
			z, name = nz, target
			continue
		}

		ans, used := s.collect(z, d, recs, lname, name, q.Qtype, client)
		usedClient = usedClient || used
		m.Answer = append(m.Answer, ans...)
		if len(ans) == 0 {
			m.Ns = append(m.Ns, z.soa(d.serial)) // NODATA
		}
		return usedClient
	}
}

// referral answers with the NS records of a delegated child and the glue
// addresses this zone holds for them.
func (s *Server) referral(m *dns.Msg, d *zoneData, cut string) {
	for _, r := range d.records[cut] {
		if r.rr == nil || r.rr.Header().Rrtype != dns.TypeNS {
			continue
		}
		m.Ns = append(m.Ns, dns.Copy(r.rr))
		target := strings.ToLower(r.rr.(*dns.NS).Ns)
		if !dns.IsSubDomain(d.origin, target) {
			continue
		}
		for _, g := range d.records[target] {
			if g.rr != nil && (g.rr.Header().Rrtype == dns.TypeA || g.rr.Header().Rrtype == dns.TypeAAAA) {
				m.Extra = append(m.Extra, dns.Copy(g.rr))
			}
		}
	}
}

// collect returns the records of an existing name matching qtype. owner is
// the queried spelling of the name (wildcard answers are synthesised for it).
func (s *Server) collect(z *zone, d *zoneData, recs []*record, lname, owner string, qtype uint16, client net.IP) ([]dns.RR, bool) {
	var out []dns.RR
	anyQ := qtype == dns.TypeANY
	apex := lname == z.origin
	if apex && (qtype == dns.TypeSOA || anyQ) {
		out = append(out, z.soa(d.serial))
	}
	if apex && (qtype == dns.TypeNS || anyQ) {
		out = append(out, z.nsRRs()...)
	}
	usedClient := false
	for _, r := range recs {
		if r.rr != nil {
			t := r.rr.Header().Rrtype
			if t != qtype && !anyQ {
				continue
			}
			if apex && t == dns.TypeNS && z.hasNS(r.rr.(*dns.NS).Ns) {
				continue // already listed from the zone's ns
			}
			rr := dns.Copy(r.rr)
			rr.Header().Name = owner
			out = append(out, rr)
			continue
		}
		// A dynamic record of type A hands out IPv4, one of type AAAA IPv6.
		wantA := r.Type == "A" && (qtype == dns.TypeA || anyQ)
		wantAAAA := r.Type == "AAAA" && (qtype == dns.TypeAAAA || anyQ)
		if !wantA && !wantAAAA {
			continue
		}
		usedClient = usedClient || len(r.rules) > 0 || (len(r.country) > 0 && s.geo != nil)
		for _, ep := range s.pick(r, client) {
			if wantA && ep.IPv4 != "" {
				if ip := net.ParseIP(ep.IPv4).To4(); ip != nil {
					out = append(out, &dns.A{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: r.TTL}, A: ip})
				}
			}
			if wantAAAA && ep.IPv6 != "" {
				if ip := net.ParseIP(ep.IPv6); ip != nil && ip.To4() == nil {
					out = append(out, &dns.AAAA{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: r.TTL}, AAAA: ip})
				}
			}
		}
	}
	return out, usedClient
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
	if client != nil {
		healthy = s.preferRegion(r, client, healthy)
	}

	n := r.MaxAnswers
	if n <= 0 || n > len(healthy) {
		n = len(healthy)
	}
	return s.weightedSample(healthy, n)
}

// preferRegion keeps the nodes of the client's region when that region has
// one. The region comes from, in order: the first prefer_region CIDR that
// contains the client, a prefer_country rule for its GeoIP country, one for
// its continent. A region without candidates falls through to the next; when
// none applies every candidate is kept.
func (s *Server) preferRegion(r *record, client net.IP, eps []api.Endpoint) []api.Endpoint {
	in := func(region string) []api.Endpoint {
		var local []api.Endpoint
		for _, e := range eps {
			if region != "" && e.Region == region {
				local = append(local, e)
			}
		}
		return local
	}
	for _, rule := range r.rules {
		if rule.net.Contains(client) {
			if local := in(rule.region); len(local) > 0 {
				return local
			}
			break
		}
	}
	if len(r.country) == 0 || s.geo == nil {
		return eps
	}
	country, continent := s.geo.lookup(client)
	if local := in(countryRegion(r.country, country)); len(local) > 0 {
		return local
	}
	if local := in(continentRegion(r.country, continent)); len(local) > 0 {
		return local
	}
	return eps
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
