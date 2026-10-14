package proxy

import (
	"sync"
	"time"
)

// limiter is a fixed-window counter per client with a ban period. It is
// sharded to keep lock contention low under floods.
type limiter struct {
	shards [64]limShard
}

type limShard struct {
	mu sync.Mutex
	m  map[string]*limEntry
}

type limEntry struct {
	windowStart time.Time
	count       int
	bannedUntil time.Time
}

// maxShardEntries bounds memory under floods from many addresses.
const maxShardEntries = 16384

// evictLocked drops a few entries that are not banned, oldest window first
// among a random sample (map iteration order is random).
func (sh *limShard) evictLocked(now time.Time) {
	var victim string
	var oldest time.Time
	n := 0
	for k, e := range sh.m {
		if n++; n > 16 {
			break
		}
		if now.Before(e.bannedUntil) {
			continue
		}
		if victim == "" || e.windowStart.Before(oldest) {
			victim, oldest = k, e.windowStart
		}
	}
	if victim == "" {
		// Everything sampled is banned: drop one anyway to stay bounded.
		for k := range sh.m {
			victim = k
			break
		}
	}
	delete(sh.m, victim)
}

func newLimiter() *limiter {
	l := &limiter{}
	for i := range l.shards {
		l.shards[i].m = map[string]*limEntry{}
	}
	return l
}

func fnv(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// allow reports whether key may proceed.
func (l *limiter) allow(key string, limit int, window, ban time.Duration, now time.Time) bool {
	sh := &l.shards[fnv(key)%uint32(len(l.shards))]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := sh.m[key]
	if !ok {
		if len(sh.m) >= maxShardEntries {
			sh.evictLocked(now)
		}
		e = &limEntry{windowStart: now}
		sh.m[key] = e
	}
	if now.Before(e.bannedUntil) {
		return false
	}
	if now.Sub(e.windowStart) >= window {
		e.windowStart, e.count = now, 0
	}
	e.count++
	if e.count > limit {
		e.bannedUntil = now.Add(ban)
		return false
	}
	return true
}

// gc removes idle entries.
func (l *limiter) gc(now time.Time, idle time.Duration) {
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		for k, e := range sh.m {
			if now.Sub(e.windowStart) > idle && now.After(e.bannedUntil) {
				delete(sh.m, k)
			}
		}
		sh.mu.Unlock()
	}
}
