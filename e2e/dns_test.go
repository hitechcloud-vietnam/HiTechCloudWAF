package e2e

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// A minimal DNS client (RFC 1035) so the suite needs no third-party module:
// one question over UDP, answers parsed with name compression.

const (
	dnsTypeA   = 1
	dnsTypeSOA = 6
	dnsClassIN = 1

	rcodeNoError  = 0
	rcodeNXDomain = 3
)

type dnsRR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

// IP returns the address of an A record.
func (r dnsRR) IP() net.IP {
	if r.Type == dnsTypeA && len(r.Data) == 4 {
		return net.IP(r.Data)
	}
	return nil
}

type dnsReply struct {
	ID            uint16
	Authoritative bool
	Truncated     bool
	Rcode         int
	Answer        []dnsRR
	Authority     []dnsRR
}

// IPv4s lists the A records of the answer section.
func (r *dnsReply) IPv4s() []string {
	var out []string
	for _, rr := range r.Answer {
		if ip := rr.IP(); ip != nil {
			out = append(out, ip.String())
		}
	}
	return out
}

func (r *dnsReply) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "rcode=%d aa=%v answers=[", r.Rcode, r.Authoritative)
	for i, rr := range r.Answer {
		if i > 0 {
			b.WriteString(" ")
		}
		if ip := rr.IP(); ip != nil {
			fmt.Fprintf(&b, "%s A %s", rr.Name, ip)
		} else {
			fmt.Fprintf(&b, "%s type%d", rr.Name, rr.Type)
		}
	}
	fmt.Fprintf(&b, "] authority=%d", len(r.Authority))
	return b.String()
}

// encodeName writes a domain name as length-prefixed labels.
func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	var out []byte
	if name != "" {
		for _, l := range strings.Split(name, ".") {
			if l == "" || len(l) > 63 {
				return nil, fmt.Errorf("invalid label in %q", name)
			}
			out = append(out, byte(len(l)))
			out = append(out, l...)
		}
	}
	if len(out) > 254 {
		return nil, fmt.Errorf("name %q too long", name)
	}
	return append(out, 0), nil
}

func buildQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	q := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(q[0:], id)
	binary.BigEndian.PutUint16(q[2:], 0) // standard query, RD=0 (authoritative server)
	binary.BigEndian.PutUint16(q[4:], 1) // QDCOUNT
	n, err := encodeName(name)
	if err != nil {
		return nil, err
	}
	q = append(q, n...)
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = binary.BigEndian.AppendUint16(q, dnsClassIN)
	return q, nil
}

// readName decodes a possibly compressed name at off and returns it with the
// offset just after it in the original position.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	end := -1
	for jumps := 0; ; {
		if off >= len(msg) {
			return "", 0, errors.New("name runs past the message")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, ".") + ".", end, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errors.New("truncated compression pointer")
			}
			if jumps++; jumps > 32 {
				return "", 0, errors.New("compression loop")
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
		case l&0xC0 != 0:
			return "", 0, fmt.Errorf("unsupported label type 0x%x", l)
		default:
			if off+1+l > len(msg) {
				return "", 0, errors.New("label runs past the message")
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

func parseRRs(msg []byte, off, count int) ([]dnsRR, int, error) {
	out := make([]dnsRR, 0, count)
	for i := 0; i < count; i++ {
		name, next, err := readName(msg, off)
		if err != nil {
			return nil, 0, err
		}
		off = next
		if off+10 > len(msg) {
			return nil, 0, errors.New("truncated resource record")
		}
		rr := dnsRR{
			Name:  strings.ToLower(name),
			Type:  binary.BigEndian.Uint16(msg[off:]),
			Class: binary.BigEndian.Uint16(msg[off+2:]),
			TTL:   binary.BigEndian.Uint32(msg[off+4:]),
		}
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, 0, errors.New("truncated rdata")
		}
		rr.Data = append([]byte(nil), msg[off:off+rdlen]...)
		off += rdlen
		out = append(out, rr)
	}
	return out, off, nil
}

func parseReply(msg []byte) (*dnsReply, error) {
	if len(msg) < 12 {
		return nil, errors.New("reply shorter than a DNS header")
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	if flags&0x8000 == 0 {
		return nil, errors.New("not a response (QR=0)")
	}
	r := &dnsReply{
		ID:            binary.BigEndian.Uint16(msg[0:]),
		Authoritative: flags&0x0400 != 0,
		Truncated:     flags&0x0200 != 0,
		Rcode:         int(flags & 0x000F),
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	ns := int(binary.BigEndian.Uint16(msg[8:]))
	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := readName(msg, off)
		if err != nil {
			return nil, fmt.Errorf("question: %w", err)
		}
		off = next + 4
	}
	var err error
	if r.Answer, off, err = parseRRs(msg, off, an); err != nil {
		return nil, fmt.Errorf("answer: %w", err)
	}
	if r.Authority, _, err = parseRRs(msg, off, ns); err != nil {
		return nil, fmt.Errorf("authority: %w", err)
	}
	return r, nil
}

// dnsQuery sends one UDP query to server and waits up to timeout for the
// matching reply.
func dnsQuery(server, name string, qtype uint16, timeout time.Duration) (*dnsReply, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	q, err := buildQuery(id, name, qtype)
	if err != nil {
		return nil, err
	}
	conn, err := net.Dial("udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		r, err := parseReply(buf[:n])
		if err != nil {
			return nil, err
		}
		if r.ID != id {
			continue // a late reply to an earlier query
		}
		return r, nil
	}
}
