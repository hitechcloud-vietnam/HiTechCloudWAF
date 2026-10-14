// Package dnsrecord validates and builds static DNS records. It is shared by
// the DNS server (records of the configuration file) and the controller
// (records managed through the API), so both accept exactly the same input.
package dnsrecord

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Types are the static record types that can be served.
var Types = []string{"A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA"}

// MaxValueLen bounds the presentation form of a record value.
const MaxValueLen = 4096

// Supported reports whether typ (upper case) is a servable static type.
func Supported(typ string) bool {
	for _, t := range Types {
		if t == typ {
			return true
		}
	}
	return false
}

// Origin returns the lower-case FQDN of a zone name.
func Origin(zone string) string { return dns.Fqdn(strings.ToLower(strings.TrimSpace(zone))) }

// Owner returns the lower-case FQDN of name inside origin. name is "@" (or
// empty) for the apex, relative ("www", "*.app") or absolute with a trailing
// dot, in which case it must be inside origin. A wildcard is only allowed as
// the leftmost label.
func Owner(origin, name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	var fqdn string
	switch {
	case name == "" || name == "@":
		fqdn = origin
	case strings.HasSuffix(name, "."):
		fqdn = name
		if !dns.IsSubDomain(origin, fqdn) {
			return "", fmt.Errorf("name %q is outside zone %s", name, origin)
		}
	default:
		fqdn = name + "." + origin
	}
	if _, ok := dns.IsDomainName(fqdn); !ok || strings.Contains(fqdn, "..") {
		return "", fmt.Errorf("invalid name %q", name)
	}
	for i, l := range dns.SplitDomainName(fqdn) {
		if strings.Contains(l, "*") && (l != "*" || i != 0) {
			return "", fmt.Errorf("invalid name %q: a wildcard must be the whole leftmost label", name)
		}
		if strings.ContainsAny(l, " \t\\\"();$@") {
			return "", fmt.Errorf("invalid name %q", name)
		}
	}
	return fqdn, nil
}

// Relative returns fqdn relative to origin ("@" for the apex).
func Relative(origin, fqdn string) string {
	if fqdn == origin {
		return "@"
	}
	return strings.TrimSuffix(fqdn, "."+origin)
}

// Build parses one static record of zone origin. Names in the value without
// a trailing dot are relative to the zone, as in a zone file. A TXT value
// that is not quoted is taken literally (split into 255-byte strings).
func Build(origin, name, typ, value string, ttl uint32) (dns.RR, error) {
	typ = strings.ToUpper(strings.TrimSpace(typ))
	value = strings.TrimSpace(value)
	if !Supported(typ) {
		return nil, fmt.Errorf("unsupported record type %q (supported: %s)", typ, strings.Join(Types, ", "))
	}
	owner, err := Owner(origin, name)
	if err != nil {
		return nil, err
	}
	switch {
	case value == "":
		return nil, errors.New("value is required")
	case len(value) > MaxValueLen:
		return nil, fmt.Errorf("value is longer than %d bytes", MaxValueLen)
	case strings.ContainsAny(value, "\r\n"):
		return nil, errors.New("value must be a single line")
	}
	if typ == "CNAME" && owner == origin {
		return nil, errors.New("a CNAME cannot be placed at the zone apex")
	}
	hdr := dns.RR_Header{Name: owner, Rrtype: dns.StringToType[typ], Class: dns.ClassINET, Ttl: ttl}
	if typ == "TXT" && !strings.HasPrefix(value, `"`) {
		return &dns.TXT{Hdr: hdr, Txt: chunk(value, 255)}, nil
	}

	zp := dns.NewZoneParser(strings.NewReader(fmt.Sprintf("%s %d IN %s %s\n", owner, ttl, typ, value)), origin, "")
	rr, ok := zp.Next()
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("invalid %s value %q: %v", typ, value, err)
	}
	if !ok || rr == nil || rr.Header().Rrtype != hdr.Rrtype {
		return nil, fmt.Errorf("invalid %s value %q", typ, value)
	}
	if _, more := zp.Next(); more {
		return nil, fmt.Errorf("invalid %s value %q: more than one record", typ, value)
	}
	if v, ok := rr.(*dns.AAAA); ok && v.AAAA.To4() != nil {
		return nil, fmt.Errorf("invalid AAAA value %q: not an IPv6 address", value)
	}
	return rr, nil
}

func chunk(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

// Conflicts reports why rr cannot be added next to existing records of the
// same owner: a CNAME excludes any other data, and duplicates are refused.
func Conflicts(existing []dns.RR, rr dns.RR) error {
	for _, e := range existing {
		if e.Header().Rrtype == dns.TypeCNAME || rr.Header().Rrtype == dns.TypeCNAME {
			return fmt.Errorf("%s already has records; a CNAME cannot coexist with other data", rr.Header().Name)
		}
		if dns.IsDuplicate(e, rr) {
			return fmt.Errorf("duplicate record %s", strings.Join(strings.Fields(rr.String()), " "))
		}
	}
	return nil
}
