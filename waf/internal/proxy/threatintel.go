package proxy

import (
	"context"
	"net"
	"net/http"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

// ThreatIntel tells whether an address is on a threat-intelligence feed,
// and which one.
type ThreatIntel interface {
	Lookup(net.IP) (feed string, listed bool)
}

// GoodBots verifies crawlers that claim a well-known User-Agent.
type GoodBots interface {
	Verify(ctx context.Context, ip net.IP, ua string) (bot string, verified bool)
}

// threatIntel applies the site's threat_intel action. It reports whether
// the request may continue and, in challenge mode, the feed that listed the
// client (the request must then pass the anti-bot challenge).
func (e *Engine) threatIntel(w http.ResponseWriter, r *http.Request, s *siteRT, ip net.IP) (challengeFeed string, cont bool) {
	mode := s.site.ThreatIntel
	if mode == "" || mode == model.ModeOff || e.opt.ThreatIntel == nil {
		return "", true
	}
	feed, listed := e.opt.ThreatIntel.Lookup(ip)
	if !listed {
		return "", true
	}
	switch mode {
	case model.ModeBlock:
		ev := e.event(r, s, ip, "threat_intel", "block", http.StatusForbidden)
		ev.Feed = feed
		e.block(w, r, ev)
		return "", false
	case model.ModeMonitor:
		ev := e.event(r, s, ip, "threat_intel", "monitor", 0)
		ev.Feed = feed
		e.opt.Events.Add(ev)
		return "", true
	case model.ThreatIntelChallenge:
		return feed, true
	}
	return "", true
}

// verifiedBot reports whether the request comes from a search engine
// crawler verified by forward-confirmed reverse DNS.
func (e *Engine) verifiedBot(r *http.Request, s *siteRT, ip net.IP) bool {
	if !s.site.Bot.AllowVerified || e.opt.GoodBots == nil {
		return false
	}
	_, ok := e.opt.GoodBots.Verify(r.Context(), ip, r.UserAgent())
	return ok
}
