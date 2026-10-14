package model

import "fmt"

// ThreatIntelChallenge is the threat_intel action that shows listed
// addresses the anti-bot challenge instead of blocking them.
const ThreatIntelChallenge = "challenge"

// normalizeThreatIntel validates Site.ThreatIntel: what to do with clients
// listed by a threat_intel feed of the node (default off).
func normalizeThreatIntel(v *string) error {
	switch *v {
	case "":
		*v = ModeOff
	case ModeBlock, ThreatIntelChallenge, ModeMonitor, ModeOff:
	default:
		return fmt.Errorf("threat_intel must be %s, %s, %s or %s", ModeBlock, ThreatIntelChallenge, ModeMonitor, ModeOff)
	}
	return nil
}
