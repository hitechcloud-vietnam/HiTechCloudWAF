package dnsrecord

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestBuild(t *testing.T) {
	origin := Origin("Example.VN")
	ok := []struct{ name, typ, value, want string }{
		{"@", "A", "192.0.2.1", "example.vn.\t60\tIN\tA\t192.0.2.1"},
		{"WWW", "aaaa", "2001:db8::1", "www.example.vn.\t60\tIN\tAAAA\t2001:db8::1"},
		{"*.app", "CNAME", "edge", "*.app.example.vn.\t60\tIN\tCNAME\tedge.example.vn."},
		{"mail.example.vn.", "A", "192.0.2.25", "mail.example.vn.\t60\tIN\tA\t192.0.2.25"},
		{"@", "MX", "10 mail.example.vn.", "example.vn.\t60\tIN\tMX\t10 mail.example.vn."},
		{"@", "TXT", "v=spf1 -all", "example.vn.\t60\tIN\tTXT\t\"v=spf1 -all\""},
		{"@", "TXT", `"a" "b"`, "example.vn.\t60\tIN\tTXT\t\"a\" \"b\""},
		{"sub", "NS", "ns1.sub", "sub.example.vn.\t60\tIN\tNS\tns1.sub.example.vn."},
		{"_sip._tcp", "SRV", "10 60 5060 sip.example.vn.", "_sip._tcp.example.vn.\t60\tIN\tSRV\t10 60 5060 sip.example.vn."},
		{"@", "CAA", `0 issue "letsencrypt.org"`, "example.vn.\t60\tIN\tCAA\t0 issue \"letsencrypt.org\""},
	}
	for _, c := range ok {
		rr, err := Build(origin, c.name, c.typ, c.value, 60)
		if err != nil {
			t.Errorf("%s %s %q: %v", c.name, c.typ, c.value, err)
			continue
		}
		if rr.String() != c.want {
			t.Errorf("%s %s: got %q want %q", c.name, c.typ, rr.String(), c.want)
		}
	}

	bad := []struct{ name, typ, value string }{
		{"@", "CNAME", "other.example.com."},            // apex CNAME
		{"www", "PTR", "x.example.vn."},                 // unsupported type
		{"www", "SOA", "a b 1 2 3 4 5"},                 // unsupported type
		{"www", "A", "2001:db8::1"},                     // wrong family
		{"www", "AAAA", "192.0.2.1"},                    // wrong family
		{"www", "A", ""},                                // empty
		{"www", "A", "192.0.2.1\nevil 60 IN A 1.2.3.4"}, // injection
		{"www", "MX", "mail.example.vn."},               // missing preference
		{"a.*", "A", "192.0.2.1"},                       // wildcard not leftmost
		{"a*b", "A", "192.0.2.1"},                       // partial wildcard
		{"www.other.com.", "A", "192.0.2.1"},            // outside the zone
		{"bad name", "A", "192.0.2.1"},
		{"x", "TXT", strings.Repeat("a", MaxValueLen+1)},
	}
	for _, c := range bad {
		if _, err := Build(origin, c.name, c.typ, c.value, 60); err == nil {
			t.Errorf("accepted %s %s %q", c.name, c.typ, c.value)
		}
	}
}

func TestLongTXTIsSplit(t *testing.T) {
	rr, err := Build("example.vn.", "dkim", "TXT", strings.Repeat("k", 600), 60)
	if err != nil {
		t.Fatal(err)
	}
	if txt := rr.(*dns.TXT).Txt; len(txt) != 3 || len(txt[0]) != 255 || strings.Join(txt, "") != strings.Repeat("k", 600) {
		t.Fatalf("chunks = %d", len(txt))
	}
}

func TestConflicts(t *testing.T) {
	a, _ := Build("example.vn.", "www", "A", "192.0.2.1", 60)
	a2, _ := Build("example.vn.", "www", "A", "192.0.2.2", 300)
	dup, _ := Build("example.vn.", "www", "A", "192.0.2.1", 300)
	cname, _ := Build("example.vn.", "www", "CNAME", "edge", 60)
	if Conflicts([]dns.RR{a}, a2) != nil {
		t.Fatal("two A records must coexist")
	}
	if Conflicts([]dns.RR{a}, dup) == nil || Conflicts([]dns.RR{a}, cname) == nil || Conflicts([]dns.RR{cname}, a) == nil {
		t.Fatal("conflict not detected")
	}
	if Relative("example.vn.", "www.example.vn.") != "www" || Relative("example.vn.", "example.vn.") != "@" {
		t.Fatal("Relative")
	}
}
