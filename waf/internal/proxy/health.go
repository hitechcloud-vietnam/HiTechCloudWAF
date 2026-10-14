package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

// UpstreamStatus is reported by the management API.
type UpstreamStatus struct {
	URL       string    `json:"url"`
	Healthy   bool      `json:"healthy"`
	Checked   bool      `json:"checked"`
	LastCheck time.Time `json:"last_check,omitempty"`
	LastError string    `json:"last_error,omitempty"`
}

func (e *Engine) sites() []*siteRT {
	seen := map[*siteRT]bool{}
	var out []*siteRT
	for _, pr := range e.rt.Load().ports {
		for _, s := range pr.allSites() {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].site.ID < out[j].site.ID })
	return out
}

// healthLoop runs due checks every second until ctx is done.
func (e *Engine) healthLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			e.runHealthChecks(ctx, now)
		}
	}
}

func (e *Engine) runHealthChecks(ctx context.Context, now time.Time) {
	for _, s := range e.sites() {
		hc := s.site.Health
		if hc.Path == "" {
			continue
		}
		for _, u := range s.upstreams {
			u.hcMu.Lock()
			due := now.Sub(u.lastCheck) >= time.Duration(hc.IntervalSec)*time.Second
			if due {
				u.lastCheck = now // also marks the check as in flight
			}
			u.hcMu.Unlock()
			if due {
				go e.checkUpstream(ctx, s, u)
			}
		}
	}
}

// checkUpstream performs one probe and updates the upstream's state.
func (e *Engine) checkUpstream(ctx context.Context, s *siteRT, u *upstream) {
	hc := s.site.Health
	ctx, cancel := context.WithTimeout(ctx, time.Duration(hc.TimeoutSec)*time.Second)
	defer cancel()
	target := *u.url
	target.Path = hc.Path
	target.RawQuery = ""
	errText := ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err == nil {
		req.Host = s.site.UpstreamHost
		if req.Host == "" && len(s.site.ServerNames) > 0 && s.site.ServerNames[0] != "_" {
			req.Host = s.site.ServerNames[0]
		}
		req.Header.Set("User-Agent", "hitechcloud-waf-healthcheck/1")
		resp, rerr := u.proxy.Transport.RoundTrip(req)
		if rerr != nil {
			errText = rerr.Error()
		} else {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			if resp.StatusCode >= 400 {
				errText = fmt.Sprintf("HTTP %d", resp.StatusCode)
			}
		}
	} else {
		errText = err.Error()
	}

	u.hcMu.Lock()
	defer u.hcMu.Unlock()
	u.lastError = errText
	if errText != "" {
		u.fails++
		u.oks = 0
		if u.fails >= hc.Unhealthy && !u.unhealthy.Load() {
			u.unhealthy.Store(true)
			e.opt.Log.Warn("upstream marked unhealthy", "site", s.site.ID, "upstream", u.url.String(), "err", errText)
		}
		return
	}
	u.oks++
	u.fails = 0
	if u.unhealthy.Load() && u.oks >= hc.Healthy {
		u.unhealthy.Store(false)
		e.opt.Log.Info("upstream healthy again", "site", s.site.ID, "upstream", u.url.String())
	}
}

// carryHealth keeps health state across configuration reloads for
// upstreams that still exist on the same site.
func carryHealth(old, next *runtime) {
	prev := map[string]*upstream{}
	for _, pr := range old.ports {
		for _, s := range pr.allSites() {
			for _, u := range s.upstreams {
				prev[fmt.Sprintf("%d|%s", s.site.ID, u.url)] = u
			}
		}
	}
	for _, pr := range next.ports {
		for _, s := range pr.allSites() {
			for _, u := range s.upstreams {
				if o, ok := prev[fmt.Sprintf("%d|%s", s.site.ID, u.url)]; ok && s.site.Health.Path != "" {
					o.hcMu.Lock()
					u.unhealthy.Store(o.unhealthy.Load())
					u.fails, u.oks, u.lastCheck, u.lastError = o.fails, o.oks, o.lastCheck, o.lastError
					o.hcMu.Unlock()
				}
			}
		}
	}
}

// UpstreamStatus returns the health of every site's upstreams.
func (e *Engine) UpstreamStatus() map[int][]UpstreamStatus {
	out := map[int][]UpstreamStatus{}
	for _, s := range e.sites() {
		for _, u := range s.upstreams {
			u.hcMu.Lock()
			st := UpstreamStatus{URL: u.url.String(), Healthy: !u.unhealthy.Load() && u.downUntil.Load() < time.Now().UnixNano(),
				Checked: s.site.Health.Path != "" && !u.lastCheck.IsZero(), LastError: u.lastError}
			if st.Checked {
				st.LastCheck = u.lastCheck.UTC()
			}
			u.hcMu.Unlock()
			out[s.site.ID] = append(out[s.site.ID], st)
		}
	}
	return out
}
