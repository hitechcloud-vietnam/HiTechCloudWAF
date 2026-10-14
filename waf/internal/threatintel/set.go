// Package threatintel blocks requests from addresses published in IP
// reputation feeds (FireHOL, Spamhaus DROP, ...) and verifies search engine
// crawlers that claim a well-known User-Agent.
package threatintel

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// u128 is an IPv6 address as a number.
type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo) }

func (a u128) inc() (u128, bool) {
	lo := a.lo + 1
	hi := a.hi
	if lo == 0 {
		hi++
		if hi == 0 {
			return u128{}, false // overflow
		}
	}
	return u128{hi, lo}, true
}

func to128(a netip.Addr) u128 {
	b := a.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

type range4 struct{ lo, hi uint32 }
type range6 struct{ lo, hi u128 }

// Set is an immutable set of address ranges with O(log n) lookups. IPv4
// and IPv6 ranges are kept apart, sorted and merged so that they never
// overlap.
type Set struct {
	v4 []range4
	v6 []range6
	// Entries is the number of valid lines in the source list.
	Entries int
	// Invalid counts lines that were neither comments nor addresses.
	Invalid int
}

// Ranges is the number of disjoint ranges after merging.
func (s *Set) Ranges() int {
	if s == nil {
		return 0
	}
	return len(s.v4) + len(s.v6)
}

// Contains reports whether a is in the set.
func (s *Set) Contains(a netip.Addr) bool {
	if s == nil || !a.IsValid() {
		return false
	}
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		x := binary.BigEndian.Uint32(b[:])
		// first range starting after x; the one before may contain it
		i := sort.Search(len(s.v4), func(i int) bool { return s.v4[i].lo > x })
		return i > 0 && x <= s.v4[i-1].hi
	}
	x := to128(a)
	i := sort.Search(len(s.v6), func(i int) bool { return x.less(s.v6[i].lo) })
	return i > 0 && !s.v6[i-1].hi.less(x)
}

// errNoEntries flags a download that is not an address list at all (for
// example an HTML error page served with status 200).
var errNoEntries = errors.New("no IP/CIDR entries found")

// Parse reads a plain-text list: one address, CIDR or "a-b" range per line.
// Text after "#" or ";" is a comment, and only the first field of a line is
// used, so FireHOL .netset/.ipset and Spamhaus DROP ("1.2.3.0/24 ; SBL1")
// files load as they are. Prefixes of length 0 are ignored.
func Parse(r io.Reader) (*Set, error) {
	s := &Set{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		tok := f[0]
		// "a - b" written with spaces
		if len(f) >= 3 && f[1] == "-" {
			tok = f[0] + "-" + f[2]
		}
		if !s.add(tok) {
			s.Invalid++
			continue
		}
		s.Entries++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if s.Entries == 0 && s.Invalid > 0 {
		return nil, errNoEntries
	}
	s.merge()
	return s, nil
}

func (s *Set) add(tok string) bool {
	if lo, hi, ok := strings.Cut(tok, "-"); ok {
		a, err1 := netip.ParseAddr(lo)
		b, err2 := netip.ParseAddr(hi)
		if err1 != nil || err2 != nil || a.Zone() != "" || b.Zone() != "" {
			return false
		}
		a, b = a.Unmap(), b.Unmap()
		if a.Is4() != b.Is4() || b.Less(a) {
			return false
		}
		s.addRange(a, b)
		return true
	}
	var p netip.Prefix
	if strings.Contains(tok, "/") {
		var err error
		if p, err = netip.ParsePrefix(tok); err != nil {
			return false
		}
		if p.Addr().Is4In6() {
			// ::ffff:1.2.3.0/120 → 1.2.3.0/24
			if p.Bits() < 96 {
				return false
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
	} else {
		a, err := netip.ParseAddr(tok)
		if err != nil || a.Zone() != "" {
			return false
		}
		a = a.Unmap()
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Bits() == 0 {
		// "0.0.0.0/0" would match everybody: never what a feed means.
		return false
	}
	p = p.Masked()
	s.addRange(p.Addr(), lastAddr(p))
	return true
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr()
	if a.Is4() {
		b := a.As4()
		x := binary.BigEndian.Uint32(b[:]) | (^uint32(0) >> p.Bits())
		binary.BigEndian.PutUint32(b[:], x)
		return netip.AddrFrom4(b)
	}
	b := a.As16()
	hi, lo := binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
	if p.Bits() < 64 {
		hi |= ^uint64(0) >> p.Bits()
		lo = ^uint64(0)
	} else {
		lo |= ^uint64(0) >> (p.Bits() - 64)
	}
	binary.BigEndian.PutUint64(b[:8], hi)
	binary.BigEndian.PutUint64(b[8:], lo)
	return netip.AddrFrom16(b)
}

func (s *Set) addRange(a, b netip.Addr) {
	if a.Is4() {
		x, y := a.As4(), b.As4()
		s.v4 = append(s.v4, range4{binary.BigEndian.Uint32(x[:]), binary.BigEndian.Uint32(y[:])})
		return
	}
	s.v6 = append(s.v6, range6{to128(a), to128(b)})
}

func (s *Set) merge() {
	sort.Slice(s.v4, func(i, j int) bool { return s.v4[i].lo < s.v4[j].lo })
	out4 := s.v4[:0]
	for _, r := range s.v4 {
		if n := len(out4); n > 0 && (out4[n-1].hi == ^uint32(0) || r.lo <= out4[n-1].hi+1) {
			if r.hi > out4[n-1].hi {
				out4[n-1].hi = r.hi
			}
			continue
		}
		out4 = append(out4, r)
	}
	s.v4 = append([]range4(nil), out4...)

	sort.Slice(s.v6, func(i, j int) bool { return s.v6[i].lo.less(s.v6[j].lo) })
	out6 := s.v6[:0]
	for _, r := range s.v6 {
		if n := len(out6); n > 0 {
			next, ok := out6[n-1].hi.inc()
			if !ok || !next.less(r.lo) {
				if out6[n-1].hi.less(r.hi) {
					out6[n-1].hi = r.hi
				}
				continue
			}
		}
		out6 = append(out6, r)
	}
	s.v6 = append([]range6(nil), out6...)
}
