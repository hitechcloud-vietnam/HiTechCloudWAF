package proxy

import (
	"context"
	"math/rand/v2"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

// balancer chooses the upstream of each request of one site. Every strategy
// only considers the best tier of upstreams available:
//
//  1. not failed by the active health check and not recently erroring;
//  2. otherwise not failed by the health check (recent errors ignored);
//  3. otherwise all of them, rather than failing every request.
type balancer struct {
	strategy string
	weights  []int
	inflight []atomic.Int64

	mu      sync.Mutex
	current []int // smooth weighted round-robin state

	ring []ringPoint // ip_hash

	sticky bool
	cookie string
	ttl    int
	ids    []string       // opaque sticky id of each upstream
	byID   map[string]int // id → upstream index
}

type ringPoint struct {
	hash uint64
	idx  int
}

// stickyKey carries the sticky cookie value to hand out with the response.
type stickyKey struct{}

// Ring size: 100 points per unit of weight, at most ~20000 points per site.
const (
	ringPointsPerWeight = 100
	ringMaxPoints       = 20000
)

func (e *Engine) newBalancer(s *siteRT, weights []int) *balancer {
	n := len(s.upstreams)
	b := &balancer{
		strategy: s.site.LB, weights: weights, inflight: make([]atomic.Int64, n), current: make([]int, n),
		sticky: s.site.Sticky, cookie: s.site.StickyCookie, ttl: s.site.StickyTTLSec,
		ids: make([]string, n), byID: make(map[string]int, n),
	}
	if b.strategy == "" {
		b.strategy = model.LBRoundRobin
	}
	if b.cookie == "" {
		b.cookie = model.DefaultStickyCookie
	}
	// Keys depend on the upstream URL (and its occurrence when listed twice),
	// not on its position, so adding or removing an upstream leaves the
	// others' ring points and sticky ids unchanged.
	seen := map[string]int{}
	keys := make([]string, n)
	for i, u := range s.upstreams {
		k := u.url.String()
		keys[i] = k + "#" + strconv.Itoa(seen[k])
		seen[k]++
		// Not bound to the site ID: IDs differ between cluster nodes, and
		// the browser scopes the cookie to the site anyway.
		b.ids[i] = e.mac("sticky", keys[i])[:22]
		b.byID[b.ids[i]] = i
	}
	if b.strategy == model.LBIPHash {
		b.ring = buildRing(keys, weights)
	}
	return b
}

func buildRing(keys []string, weights []int) []ringPoint {
	total := 0
	for _, w := range weights {
		total += w
	}
	var ring []ringPoint
	for i, k := range keys {
		per := ringPointsPerWeight * weights[i]
		if total*ringPointsPerWeight > ringMaxPoints {
			per = max(8, weights[i]*ringMaxPoints/total)
		}
		for v := 0; v < per; v++ {
			ring = append(ring, ringPoint{hash: hash64([]byte(k + "#" + strconv.Itoa(v))), idx: i})
		}
	}
	sort.Slice(ring, func(a, b int) bool { return ring[a].hash < ring[b].hash })
	return ring
}

// hash64 is FNV-1a with a splitmix64 finalizer for an even spread.
func hash64(b []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	h ^= h >> 30
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 27
	h *= 0x94d049bb133111eb
	h ^= h >> 31
	return h
}

// clientHashKey is the address hashed by ip_hash: IPv4 as is, IPv6 by /64
// (privacy addresses rotate inside the prefix).
func clientHashKey(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	if v6 := ip.To16(); v6 != nil {
		return v6[:8]
	}
	return nil
}

// candidates returns the indices of the best available tier, ascending.
func candidates(ups []*upstream, buf []int) []int {
	now := time.Now().UnixNano()
	c := buf[:0]
	for i, u := range ups {
		if !u.unhealthy.Load() && u.downUntil.Load() < now {
			c = append(c, i)
		}
	}
	if len(c) > 0 {
		return c
	}
	for i, u := range ups {
		if !u.unhealthy.Load() {
			c = append(c, i)
		}
	}
	if len(c) > 0 {
		return c
	}
	for i := range ups {
		c = append(c, i)
	}
	return c
}

// choose picks an upstream index for the request. stickyID is the cookie
// value to set on the response ("" = keep the client's cookie).
func (s *siteRT) choose(r *http.Request, ip net.IP) (idx int, stickyID string) {
	b := s.lb
	var buf [16]int
	cands := candidates(s.upstreams, buf[:])
	if b.sticky {
		if c, err := r.Cookie(b.cookie); err == nil {
			if i, ok := b.byID[c.Value]; ok && inSorted(cands, i) {
				return i, ""
			}
		}
	}
	idx = s.strategyPick(cands, ip)
	if b.sticky {
		stickyID = b.ids[idx]
	}
	return idx, stickyID
}

func inSorted(list []int, v int) bool {
	i := sort.SearchInts(list, v)
	return i < len(list) && list[i] == v
}

func (s *siteRT) strategyPick(cands []int, ip net.IP) int {
	b := s.lb
	if len(cands) == 1 {
		return cands[0]
	}
	switch b.strategy {
	case model.LBWeighted:
		// Smooth weighted round-robin (as nginx): interleaves instead of
		// sending bursts to the heaviest upstream.
		b.mu.Lock()
		defer b.mu.Unlock()
		total, best := 0, -1
		for _, i := range cands {
			b.current[i] += b.weights[i]
			total += b.weights[i]
			if best < 0 || b.current[i] > b.current[best] {
				best = i
			}
		}
		b.current[best] -= total
		return best
	case model.LBLeastConn:
		// Lowest in-flight/weight; the rotating start spreads ties.
		start := int(s.rr.Add(1))
		best := -1
		var bestLoad int64
		for k := range cands {
			i := cands[(start+k)%len(cands)]
			load := b.inflight[i].Load()
			if best < 0 || load*int64(b.weights[best]) < bestLoad*int64(b.weights[i]) {
				best, bestLoad = i, load
			}
		}
		return best
	case model.LBRandom:
		total := 0
		for _, i := range cands {
			total += b.weights[i]
		}
		n := rand.IntN(total) //nolint:gosec // load spreading, not security
		for _, i := range cands {
			if n < b.weights[i] {
				return i
			}
			n -= b.weights[i]
		}
		return cands[len(cands)-1]
	case model.LBIPHash:
		if key := clientHashKey(ip); key != nil && len(b.ring) > 0 {
			var okBuf [64]bool
			ok := okBuf[:]
			if len(s.upstreams) > len(ok) {
				ok = make([]bool, len(s.upstreams))
			}
			for _, i := range cands {
				ok[i] = true
			}
			// Walk clockwise to the first point of an available upstream:
			// clients of the other upstreams keep theirs.
			h := hash64(key)
			p := sort.Search(len(b.ring), func(k int) bool { return b.ring[k].hash >= h })
			for k := 0; k < len(b.ring); k++ {
				if pt := b.ring[(p+k)%len(b.ring)]; ok[pt.idx] {
					return pt.idx
				}
			}
		}
	}
	// round_robin: the first available upstream from a rotating start.
	n := len(s.upstreams)
	start := int(s.rr.Add(1)) % n
	if i := sort.SearchInts(cands, start); i < len(cands) {
		return cands[i]
	}
	return cands[0]
}

// forward proxies r to the upstream chosen for it.
func (s *siteRT) forward(w http.ResponseWriter, r *http.Request, ip net.IP) {
	if len(s.upstreams) == 0 || s.lb == nil {
		http.Error(w, "no upstream available", http.StatusBadGateway)
		return
	}
	i, stickyID := s.choose(r, ip)
	if stickyID != "" {
		r = r.WithContext(context.WithValue(r.Context(), stickyKey{}, stickyID))
	}
	s.lb.inflight[i].Add(1)
	defer s.lb.inflight[i].Add(-1)
	s.upstreams[i].proxy.ServeHTTP(w, r)
}

// stickyCookie is added to responses of requests that were (re)assigned.
func (b *balancer) stickyCookie(id string, secure bool) string {
	c := &http.Cookie{Name: b.cookie, Value: id, Path: "/", MaxAge: b.ttl, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode}
	return c.String()
}
