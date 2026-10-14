package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
)

func newStaticDNS(t *testing.T, controllerURL string) *Server {
	t.Helper()
	if controllerURL == "" {
		controllerURL = "https://controller.example:7443"
	}
	cfg := &config.DNS{
		ControllerURL: controllerURL, Token: "dns",
		Zones: []config.Zone{
			{
				Name: "example.vn", NS: []string{"ns1.example.vn", "ns2.example.vn"}, Hostmaster: "noc.example.vn", TTL: 30, Serial: 100,
				Records: []config.Record{
					{Name: "ns1", Type: "A", Value: "192.0.2.53"},
					{Name: "@", Type: "MX", Value: "10 mail"},
					{Name: "@", Type: "TXT", Value: "v=spf1 include:_spf.example.vn -all"},
					{Name: "@", Type: "CAA", Value: `0 issue "letsencrypt.org"`},
					{Name: "_sip._tcp", Type: "SRV", Value: "10 60 5060 sip.example.vn."},
					{Name: "mail", Type: "A", Value: "192.0.2.25"},
					{Name: "*.app", Type: "A", Value: "192.0.2.80"},
					{Name: "*.app", Type: "TXT", Value: "wild"},
					{Name: "exact.app", Type: "TXT", Value: "exact"},
					{Name: "a.b.deep", Type: "A", Value: "192.0.2.90"},
					{Name: "*.edge", Pool: "web"},
					{Name: "alias", Type: "CNAME", Value: "mail"},
					{Name: "chain", Type: "CNAME", Value: "alias.example.vn."},
					{Name: "ext", Type: "CNAME", Value: "www.example.com."},
					{Name: "loop1", Type: "CNAME", Value: "loop2"},
					{Name: "loop2", Type: "CNAME", Value: "loop1"},
					{Name: "dangling", Type: "CNAME", Value: "missing"},
					{Name: "sub", Type: "NS", Value: "ns.sub"},
					{Name: "ns.sub", Type: "A", Value: "192.0.2.54"},
				},
			},
			{Name: "other.vn", NS: []string{"ns1.example.vn"}, TTL: 60, Serial: 5},
		},
	}
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.SetPool("web", []api.Endpoint{{NodeID: "a", IPv4: "203.0.113.1", Weight: 100, Healthy: true}})
	return s
}

func types(rrs []dns.RR) string {
	var out []string
	for _, rr := range rrs {
		out = append(out, dns.TypeToString[rr.Header().Rrtype])
	}
	return strings.Join(out, ",")
}

func TestStaticRecordTypes(t *testing.T) {
	s := newStaticDNS(t, "")
	m := query(s, "example.vn.", dns.TypeMX, "192.0.2.1")
	if len(m.Answer) != 1 || m.Answer[0].(*dns.MX).Mx != "mail.example.vn." {
		t.Fatalf("MX = %v", m.Answer)
	}
	m = query(s, "example.vn.", dns.TypeTXT, "192.0.2.1")
	if len(m.Answer) != 1 || strings.Join(m.Answer[0].(*dns.TXT).Txt, "") != "v=spf1 include:_spf.example.vn -all" {
		t.Fatalf("unquoted TXT must be kept literally: %v", m.Answer)
	}
	if m := query(s, "example.vn.", dns.TypeCAA, "192.0.2.1"); len(m.Answer) != 1 || m.Answer[0].(*dns.CAA).Value != "letsencrypt.org" {
		t.Fatalf("CAA = %v", m.Answer)
	}
	if m := query(s, "_sip._tcp.example.vn.", dns.TypeSRV, "192.0.2.1"); len(m.Answer) != 1 || m.Answer[0].(*dns.SRV).Port != 5060 {
		t.Fatalf("SRV = %v", m.Answer)
	}
}

func TestApexSOAAndNS(t *testing.T) {
	s := newStaticDNS(t, "")
	m := query(s, "EXAMPLE.vn.", dns.TypeSOA, "192.0.2.1")
	if !m.Authoritative || len(m.Answer) != 1 || m.Answer[0].(*dns.SOA).Serial != 100 || m.Answer[0].(*dns.SOA).Ns != "ns1.example.vn." {
		t.Fatalf("SOA = %v", m.Answer)
	}
	if m := query(s, "example.vn.", dns.TypeNS, "192.0.2.1"); len(m.Answer) != 2 || types(m.Answer) != "NS,NS" {
		t.Fatalf("NS = %v", m.Answer)
	}
	// A static NS at the apex adds to the zone's ns, without duplicates.
	s.SetRecords(api.DNSRecordSet{Serial: 200, Records: []api.DNSRecord{
		{ID: "1", Zone: "example.vn", Name: "@", Type: "NS", Value: "ns3.example.net."},
		{ID: "2", Zone: "example.vn", Name: "@", Type: "NS", Value: "ns1.example.vn."},
	}})
	if m := query(s, "example.vn.", dns.TypeNS, "192.0.2.1"); len(m.Answer) != 3 {
		t.Fatalf("NS with static apex NS = %v", m.Answer)
	}
	// The controller serial moves the SOA serial forward.
	if m := query(s, "example.vn.", dns.TypeSOA, "192.0.2.1"); m.Answer[0].(*dns.SOA).Serial != 200 {
		t.Fatalf("serial = %v", m.Answer)
	}
	if m := query(s, "other.vn.", dns.TypeSOA, "192.0.2.1"); m.Answer[0].(*dns.SOA).Serial != 200 {
		t.Fatalf("other zone serial = %v", m.Answer)
	}
}

func TestNXDOMAINVersusNODATA(t *testing.T) {
	s := newStaticDNS(t, "")
	cases := []struct {
		name  string
		qtype uint16
		rcode int
	}{
		{"mail.example.vn.", dns.TypeAAAA, dns.RcodeSuccess},    // name exists, other type
		{"deep.example.vn.", dns.TypeA, dns.RcodeSuccess},       // empty non-terminal
		{"b.deep.example.vn.", dns.TypeA, dns.RcodeSuccess},     // empty non-terminal
		{"x.deep.example.vn.", dns.TypeA, dns.RcodeNameError},   // no wildcard
		{"nope.example.vn.", dns.TypeA, dns.RcodeNameError},     // nothing
		{"example.vn.", dns.TypeA, dns.RcodeSuccess},            // apex
		{"x.b.deep.example.vn.", dns.TypeA, dns.RcodeNameError}, // below an ENT
	}
	for _, c := range cases {
		m := query(s, c.name, c.qtype, "192.0.2.1")
		if m.Rcode != c.rcode || len(m.Answer) != 0 || len(m.Ns) != 1 || m.Ns[0].Header().Rrtype != dns.TypeSOA || !m.Authoritative {
			t.Errorf("%s %s: rcode=%d answer=%v ns=%v", c.name, dns.TypeToString[c.qtype], m.Rcode, m.Answer, m.Ns)
		}
	}
}

func TestWildcard(t *testing.T) {
	s := newStaticDNS(t, "")
	m := query(s, "Foo.app.example.vn.", dns.TypeA, "192.0.2.1")
	if len(m.Answer) != 1 || m.Answer[0].Header().Name != "Foo.app.example.vn." || m.Answer[0].(*dns.A).A.String() != "192.0.2.80" {
		t.Fatalf("wildcard A = %v", m.Answer)
	}
	if m := query(s, "x.y.app.example.vn.", dns.TypeA, "192.0.2.1"); len(m.Answer) != 1 {
		t.Fatalf("wildcard covers deeper names: %v", m.Answer)
	}
	// An existing name is not covered by the wildcard.
	m = query(s, "exact.app.example.vn.", dns.TypeTXT, "192.0.2.1")
	if len(m.Answer) != 1 || m.Answer[0].(*dns.TXT).Txt[0] != "exact" {
		t.Fatalf("exact TXT = %v", m.Answer)
	}
	if m := query(s, "exact.app.example.vn.", dns.TypeA, "192.0.2.1"); len(m.Answer) != 0 || m.Rcode != dns.RcodeSuccess {
		t.Fatalf("exact name must be NODATA for A, got %v", m)
	}
	if m := query(s, "app.example.vn.", dns.TypeA, "192.0.2.1"); len(m.Answer) != 0 || m.Rcode != dns.RcodeSuccess {
		t.Fatalf("wildcard parent must be NODATA, got %v", m)
	}
	// Pool records can be wildcards too.
	if got := ips(query(s, "cust1.edge.example.vn.", dns.TypeA, "192.0.2.1")); !got["203.0.113.1"] {
		t.Fatalf("wildcard pool = %v", got)
	}
}

func TestCNAMEHandling(t *testing.T) {
	s := newStaticDNS(t, "")
	m := query(s, "chain.example.vn.", dns.TypeA, "192.0.2.1")
	if types(m.Answer) != "CNAME,CNAME,A" || m.Rcode != dns.RcodeSuccess {
		t.Fatalf("chain = %v", m.Answer)
	}
	// Out-of-zone targets are left to the resolver.
	if m := query(s, "ext.example.vn.", dns.TypeA, "192.0.2.1"); types(m.Answer) != "CNAME" || len(m.Ns) != 0 {
		t.Fatalf("ext = %v", m)
	}
	// Loops stop.
	if m := query(s, "loop1.example.vn.", dns.TypeA, "192.0.2.1"); types(m.Answer) != "CNAME,CNAME" {
		t.Fatalf("loop = %v", m.Answer)
	}
	// A CNAME to a missing in-zone name: NXDOMAIN with the CNAME (RFC 6604).
	if m := query(s, "dangling.example.vn.", dns.TypeA, "192.0.2.1"); types(m.Answer) != "CNAME" || m.Rcode != dns.RcodeNameError {
		t.Fatalf("dangling = %v", m)
	}
	// CNAME target with the name but not the type: NODATA after the CNAME.
	if m := query(s, "alias.example.vn.", dns.TypeAAAA, "192.0.2.1"); types(m.Answer) != "CNAME" || len(m.Ns) != 1 {
		t.Fatalf("alias AAAA = %v", m)
	}
}

func TestDelegation(t *testing.T) {
	s := newStaticDNS(t, "")
	m := query(s, "www.sub.example.vn.", dns.TypeA, "192.0.2.1")
	if m.Authoritative || len(m.Answer) != 0 || types(m.Ns) != "NS" || types(m.Extra) != "A" {
		t.Fatalf("referral = %v", m)
	}
	if m := query(s, "sub.example.vn.", dns.TypeDS, "192.0.2.1"); !m.Authoritative || len(m.Answer) != 0 || types(m.Ns) != "SOA" {
		t.Fatalf("DS at the cut belongs to the parent: %v", m)
	}
}

func TestConfigConflictsRejected(t *testing.T) {
	for _, recs := range [][]config.Record{
		{{Name: "a", Type: "CNAME", Value: "b"}, {Name: "a", Type: "TXT", Value: "x"}},
		{{Name: "a", Pool: "web"}, {Name: "a", Type: "CNAME", Value: "b"}},
		{{Name: "@", Type: "CNAME", Value: "b"}},
		{{Name: "a", Type: "PTR", Value: "b"}},
		{{Name: "a.*", Type: "A", Value: "192.0.2.1"}},
		{{Name: "a", Type: "A", Value: "2001:db8::1"}},
	} {
		cfg := &config.DNS{ControllerURL: "https://c:1", Token: "t", Zones: []config.Zone{{Name: "example.vn", NS: []string{"ns1.example.vn"}, Records: recs}}}
		if _, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
			t.Errorf("accepted %+v", recs)
		}
	}
}

func TestControllerRecordsMergeAndConflicts(t *testing.T) {
	s := newStaticDNS(t, "")
	s.SetRecords(api.DNSRecordSet{Serial: 1, Records: []api.DNSRecord{
		{ID: "ok", Zone: "Example.VN.", Name: "api", Type: "A", Value: "192.0.2.10"},
		{ID: "wild", Zone: "example.vn", Name: "*.svc", Type: "CNAME", Value: "api"},
		{ID: "clash", Zone: "example.vn", Name: "alias", Type: "A", Value: "192.0.2.11"},   // local CNAME wins
		{ID: "bad", Zone: "example.vn", Name: "bad", Type: "A", Value: "not-an-ip"},        // skipped
		{ID: "foreign", Zone: "elsewhere.vn", Name: "www", Type: "A", Value: "192.0.2.12"}, // not served here
		{ID: "o", Zone: "other.vn", Name: "@", Type: "TXT", Value: `"hello" "world"`},      // second zone
	}})
	if got := ips(query(s, "api.example.vn.", dns.TypeA, "192.0.2.1")); !got["192.0.2.10"] {
		t.Fatalf("controller record = %v", got)
	}
	if m := query(s, "x.svc.example.vn.", dns.TypeA, "192.0.2.1"); types(m.Answer) != "CNAME,A" {
		t.Fatalf("wildcard CNAME = %v", m.Answer)
	}
	if m := query(s, "alias.example.vn.", dns.TypeA, "192.0.2.1"); types(m.Answer) != "CNAME,A" || ips(m)["192.0.2.11"] {
		t.Fatalf("conflicting controller record served: %v", m.Answer)
	}
	if m := query(s, "bad.example.vn.", dns.TypeA, "192.0.2.1"); m.Rcode != dns.RcodeNameError {
		t.Fatalf("invalid record served: %v", m)
	}
	if m := query(s, "www.elsewhere.vn.", dns.TypeA, "192.0.2.1"); m.Rcode != dns.RcodeRefused {
		t.Fatalf("foreign zone: %v", m)
	}
	if m := query(s, "other.vn.", dns.TypeTXT, "192.0.2.1"); len(m.Answer) != 1 || m.Answer[0].Header().Ttl != 60 {
		t.Fatalf("other zone TXT = %v", m.Answer)
	}
	// A new set replaces the previous one.
	s.SetRecords(api.DNSRecordSet{Serial: 2})
	if m := query(s, "api.example.vn.", dns.TypeA, "192.0.2.1"); m.Rcode != dns.RcodeNameError {
		t.Fatalf("removed record still served: %v", m)
	}
}

func TestRefreshFetchesRecordsWithETag(t *testing.T) {
	var calls, notModified atomic.Int32
	ctl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer dns" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/pools/web/endpoints":
			_, _ = w.Write([]byte(`{"pool":"web","endpoints":[]}`))
		case "/v1/dns/records":
			calls.Add(1)
			w.Header().Set("ETag", `"7"`)
			if r.Header.Get("If-None-Match") == `"7"` {
				notModified.Add(1)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = w.Write([]byte(`{"serial":7,"records":[{"id":"x","zone":"example.vn","name":"api","type":"AAAA","value":"2001:db8::7"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ctl.Close()
	s := newStaticDNS(t, ctl.URL)
	s.Refresh(context.Background())
	s.Refresh(context.Background())
	if calls.Load() != 2 || notModified.Load() != 1 {
		t.Fatalf("calls=%d notModified=%d", calls.Load(), notModified.Load())
	}
	if got := ips(query(s, "api.example.vn.", dns.TypeAAAA, "192.0.2.1")); !got["2001:db8::7"] {
		t.Fatalf("fetched record = %v", got)
	}

	// Controller down: the last known records stay.
	ctl.Close()
	s.Refresh(context.Background())
	if got := ips(query(s, "api.example.vn.", dns.TypeAAAA, "192.0.2.1")); !got["2001:db8::7"] {
		t.Fatalf("records lost while controller down: %v", got)
	}
}

func TestECSScopeZeroForStaticAnswers(t *testing.T) {
	s := newStaticDNS(t, "")
	m := new(dns.Msg)
	m.SetQuestion("mail.example.vn.", dns.TypeA)
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.Option = append(o.Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("198.51.100.0").To4()})
	m.Extra = append(m.Extra, o)
	r := s.answer(m, net.ParseIP("8.8.8.8"))
	opt := r.IsEdns0()
	if opt == nil || len(opt.Option) != 1 || opt.Option[0].(*dns.EDNS0_SUBNET).SourceScope != 0 {
		t.Fatalf("OPT = %v", opt)
	}
}
