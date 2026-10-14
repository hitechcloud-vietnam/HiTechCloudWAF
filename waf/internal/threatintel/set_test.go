package threatintel

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
)

const fireholSample = `#
# firehol_level1
#
# Maintainer      : FireHOL
#
0.0.0.0/8
1.10.16.0/20
5.188.10.0/23
10.0.0.0/8
192.0.2.7
203.0.113.0/25
203.0.113.128/25
`

const dropSample = `; Spamhaus DROP List 2026/10/14 - (c) 2026 The Spamhaus Project SLU
; Last-Modified: Tue, 14 Oct 2026 10:00:00 GMT
1.19.0.0/16 ; SBL434604
2.57.122.0/24 ; SBL636050
2001:db8:dead::/48 ; SBL999999
`

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestParseFormats(t *testing.T) {
	s, err := Parse(strings.NewReader(fireholSample + dropSample + "198.51.100.10 - 198.51.100.20\n2001:db8::1\n::ffff:198.18.0.0/112\nnot-an-ip\n0.0.0.0/0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Entries != 13 || s.Invalid != 2 {
		t.Fatalf("entries=%d invalid=%d", s.Entries, s.Invalid)
	}
	// 203.0.113.0/25 + /25 merge into one range
	if s.Ranges() != 12 {
		t.Fatalf("ranges=%d", s.Ranges())
	}
	in := []string{"1.10.16.0", "1.10.31.255", "5.188.11.200", "192.0.2.7", "203.0.113.0", "203.0.113.255",
		"1.19.200.1", "2.57.122.9", "2001:db8:dead:1::5", "198.51.100.10", "198.51.100.15", "198.51.100.20",
		"2001:db8::1", "::ffff:1.19.0.1", "198.18.1.1"}
	out := []string{"1.10.15.255", "1.10.32.0", "192.0.2.6", "192.0.2.8", "203.0.114.0", "198.51.100.21",
		"2001:db8:deae::", "2001:db8::2", "8.8.8.8", "::1", "2.57.123.0", "198.18.0.0x"}
	for _, a := range in {
		if !s.Contains(mustAddr(a)) {
			t.Errorf("%s should be listed", a)
		}
	}
	for _, a := range out {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			continue
		}
		if s.Contains(ip) {
			t.Errorf("%s should not be listed", a)
		}
	}
}

func TestParseRejectsNonLists(t *testing.T) {
	if _, err := Parse(strings.NewReader("<html><body>Rate limited</body></html>\n")); err == nil {
		t.Fatal("an HTML page must not replace a list")
	}
	s, err := Parse(strings.NewReader("# only comments\n\n"))
	if err != nil || s.Entries != 0 || s.Contains(mustAddr("1.2.3.4")) {
		t.Fatalf("empty list: %v %+v", err, s)
	}
}

func TestMergeEdges(t *testing.T) {
	s, err := Parse(strings.NewReader("255.255.255.0/24\n255.255.255.255\n128.0.0.0/1\n1.0.0.0/8\n1.2.0.0/16\nffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00/120\nffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n::2-::5\n::6\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.v4) != 2 || len(s.v6) != 2 {
		t.Fatalf("v4=%v v6=%v", s.v4, s.v6)
	}
	for _, a := range []string{"255.255.255.255", "128.0.0.0", "1.2.3.4", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::6", "::2"} {
		if !s.Contains(mustAddr(a)) {
			t.Errorf("%s should be listed", a)
		}
	}
	for _, a := range []string{"127.255.255.255", "2.0.0.0", "::7", "::1"} {
		if s.Contains(mustAddr(a)) {
			t.Errorf("%s should not be listed", a)
		}
	}
}

// TestContainsMatchesLinearScan checks the binary search against a naive
// scan of random prefixes.
func TestContainsMatchesLinearScan(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	var b strings.Builder
	var prefixes []netip.Prefix
	for range 2000 {
		var a [4]byte
		for i := range a {
			a[i] = byte(r.IntN(256))
		}
		p := netip.PrefixFrom(netip.AddrFrom4(a), 8+r.IntN(25)).Masked()
		prefixes = append(prefixes, p)
		fmt.Fprintln(&b, p)
	}
	s, err := Parse(strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	for range 5000 {
		var a [4]byte
		for i := range a {
			a[i] = byte(r.IntN(256))
		}
		ip := netip.AddrFrom4(a)
		want := false
		for _, p := range prefixes {
			if p.Contains(ip) {
				want = true
				break
			}
		}
		if s.Contains(ip) != want {
			t.Fatalf("%s: got %v want %v", ip, !want, want)
		}
	}
}

func BenchmarkContains(b *testing.B) {
	var sb strings.Builder
	r := rand.New(rand.NewPCG(3, 4))
	for range 100000 {
		fmt.Fprintf(&sb, "%d.%d.%d.0/24\n", r.IntN(256), r.IntN(256), r.IntN(256))
	}
	s, _ := Parse(strings.NewReader(sb.String()))
	ip := mustAddr("203.0.113.9")
	b.ResetTimer()
	for range b.N {
		s.Contains(ip)
	}
}
