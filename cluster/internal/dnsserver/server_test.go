package dnsserver

import (
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
)

func newDNS(t *testing.T) *Server {
	t.Helper()
	cfg := &config.DNS{
		ControllerURL: "https://controller.example:7443", Token: "dns",
		Zones: []config.Zone{{
			Name: "example.vn", NS: []string{"ns1.example.vn", "ns2.example.vn"}, Hostmaster: "noc.example.vn", TTL: 30, Serial: 1,
			Records: []config.Record{
				{Name: "www", Pool: "web", PreferRegion: []config.RegionRule{{CIDR: "198.51.100.0/24", Region: "hcm"}}},
				{Name: "www", Type: "AAAA", Pool: "web"},
				{Name: "v6", Type: "AAAA", Pool: "web"},
				{Name: "one", Pool: "web", MaxAnswers: 1},
				{Name: "open", Pool: "empty", FailOpen: true},
				{Name: "closed", Pool: "empty"},
				{Name: "shop", Type: "CNAME", Value: "www.example.vn."},
				{Name: "@", Type: "TXT", Value: `"v=spf1 -all"`},
			},
		}},
	}
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.SetPool("web", []api.Endpoint{
		{NodeID: "a", Region: "hn", IPv4: "203.0.113.1", IPv6: "2001:db8::1", Weight: 100, Healthy: true},
		{NodeID: "b", Region: "hcm", IPv4: "203.0.113.2", Weight: 100, Healthy: true},
		{NodeID: "c", Region: "hn", IPv4: "203.0.113.3", Weight: 100, Healthy: false},
	})
	s.SetPool("empty", []api.Endpoint{{NodeID: "z", IPv4: "203.0.113.9", Healthy: false}})
	return s
}

func query(s *Server, name string, t uint16, from string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, t)
	return s.answer(m, net.ParseIP(from))
}

func ips(m *dns.Msg) map[string]bool {
	out := map[string]bool{}
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			out[v.A.String()] = true
		case *dns.AAAA:
			out[v.AAAA.String()] = true
		}
	}
	return out
}

func TestHealthyOnly(t *testing.T) {
	s := newDNS(t)
	m := query(s, "WWW.example.vn.", dns.TypeA, "192.0.2.1")
	got := ips(m)
	if !m.Authoritative || len(got) != 2 || got["203.0.113.3"] {
		t.Fatalf("answer = %v", m.Answer)
	}
}

func TestRegionPreferenceViaECS(t *testing.T) {
	s := newDNS(t)
	m := new(dns.Msg)
	m.SetQuestion("www.example.vn.", dns.TypeA)
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.Option = append(o.Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("198.51.100.0").To4()})
	m.Extra = append(m.Extra, o)
	r := s.answer(m, net.ParseIP("8.8.8.8"))
	got := ips(r)
	if len(got) != 1 || !got["203.0.113.2"] {
		t.Fatalf("expected hcm node only, got %v", r.Answer)
	}
	if r.IsEdns0() == nil {
		t.Fatal("OPT not echoed")
	}
}

func TestAAAAAndMaxAnswers(t *testing.T) {
	s := newDNS(t)
	if got := ips(query(s, "www.example.vn.", dns.TypeAAAA, "192.0.2.1")); len(got) != 1 || !got["2001:db8::1"] {
		t.Fatalf("AAAA = %v", got)
	}
	if got := ips(query(s, "one.example.vn.", dns.TypeA, "192.0.2.1")); len(got) != 1 {
		t.Fatalf("max_answers ignored: %v", got)
	}
}

func TestFailOpenAndClosed(t *testing.T) {
	s := newDNS(t)
	if got := ips(query(s, "open.example.vn.", dns.TypeA, "192.0.2.1")); !got["203.0.113.9"] {
		t.Fatalf("fail_open should answer all nodes: %v", got)
	}
	m := query(s, "closed.example.vn.", dns.TypeA, "192.0.2.1")
	if len(m.Answer) != 0 || m.Rcode != dns.RcodeSuccess || len(m.Ns) != 1 {
		t.Fatalf("expected NODATA, got %v", m)
	}
}

func TestStaticNXDOMAINAndRefused(t *testing.T) {
	s := newDNS(t)
	m := query(s, "shop.example.vn.", dns.TypeA, "192.0.2.1")
	if len(m.Answer) != 1 || m.Answer[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatalf("CNAME = %v", m.Answer)
	}
	if m := query(s, "example.vn.", dns.TypeNS, "192.0.2.1"); len(m.Answer) != 2 {
		t.Fatalf("NS = %v", m.Answer)
	}
	if m := query(s, "example.vn.", dns.TypeTXT, "192.0.2.1"); len(m.Answer) != 1 {
		t.Fatalf("TXT = %v", m.Answer)
	}
	if m := query(s, "nope.example.vn.", dns.TypeA, "192.0.2.1"); m.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %d", m.Rcode)
	}
	if m := query(s, "other.com.", dns.TypeA, "192.0.2.1"); m.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED, got %d", m.Rcode)
	}
}

func TestWeightedSampleFavoursHeavyNodes(t *testing.T) {
	s := newDNS(t)
	eps := []api.Endpoint{{NodeID: "heavy", Weight: 900}, {NodeID: "light", Weight: 100}}
	first := map[string]int{}
	for i := 0; i < 2000; i++ {
		first[s.weightedSample(eps, 1)[0].NodeID]++
	}
	if first["heavy"] < 1600 || first["light"] < 100 {
		t.Fatalf("distribution = %v", first)
	}
}

func TestAAAARecordDoesNotLeakIPv4(t *testing.T) {
	s := newDNS(t)
	if got := ips(query(s, "v6.example.vn.", dns.TypeA, "192.0.2.1")); len(got) != 0 {
		t.Fatalf("AAAA pool record answered A: %v", got)
	}
}
