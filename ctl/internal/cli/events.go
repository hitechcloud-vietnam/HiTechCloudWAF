package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type event struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	SiteID   int       `json:"site_id"`
	Host     string    `json:"host"`
	ClientIP string    `json:"client_ip"`
	Country  string    `json:"country"`
	Method   string    `json:"method"`
	URI      string    `json:"uri"`
	Kind     string    `json:"kind"`
	Action   string    `json:"action"`
	Status   int       `json:"status"`
	Rules    []struct {
		ID int `json:"id"`
	} `json:"rules"`
}

// pollLimit is how many events --follow asks for on each poll.
const pollLimit = 200

func (a *App) cmdEvents(ctx context.Context, args []string) error {
	fs := a.flags("events", "[--site N] [--limit N] [--follow]")
	siteID := fs.Int("site", 0, "only events of this site ID")
	limit := fs.Int("limit", 50, "number of events (1..1000)")
	follow := fs.Bool("follow", false, "keep polling every 2s and print new events")
	fs.BoolVar(follow, "f", false, "shorthand for --follow")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	if *limit < 1 || *limit > 1000 {
		return usagef("--limit must be 1..1000")
	}
	if *siteID < 0 {
		return usagef("--site must be a site ID")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	fetch := func(n int) ([]json.RawMessage, []event, error) {
		q := url.Values{"limit": {strconv.Itoa(n)}}
		if *siteID > 0 {
			q.Set("site_id", strconv.Itoa(*siteID))
		}
		var l list[json.RawMessage]
		if err := c.do(ctx, http.MethodGet, "/api/open/events", q, nil, &l); err != nil {
			return nil, nil, err
		}
		evs := make([]event, len(l.Data))
		for i, r := range l.Data {
			if err := json.Unmarshal(r, &evs[i]); err != nil {
				return nil, nil, err
			}
		}
		return l.Data, evs, nil
	}
	if !*follow {
		raw, evs, err := fetch(*limit)
		if err != nil {
			return err
		}
		if a.json() {
			return a.printJSON(rawArray(raw))
		}
		a.eventHeader()
		for i := len(evs) - 1; i >= 0; i-- { // oldest first, like a log
			a.eventRow(evs[i])
		}
		return nil
	}

	// Follow: the API returns the newest events first; print, oldest first,
	// those whose ID was not in the previous answer.
	raw, evs, err := fetch(max(*limit, pollLimit))
	if err != nil {
		return err
	}
	if !a.json() {
		a.eventHeader()
	}
	seen := map[string]bool{}
	for _, e := range evs {
		seen[e.ID] = true
	}
	n := min(*limit, len(evs))
	for i := n - 1; i >= 0; i-- {
		a.printEvent(raw[i], evs[i])
	}
	tick := time.NewTicker(a.PollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		raw, evs, err := fetch(pollLimit)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ae *APIError
			if errors.As(err, &ae) && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden) {
				return err
			}
			fmt.Fprintf(a.Stderr, "hcwctl: %v (retrying)\n", err)
			continue
		}
		next := make(map[string]bool, len(evs))
		for i := len(evs) - 1; i >= 0; i-- {
			next[evs[i].ID] = true
			if !seen[evs[i].ID] {
				a.printEvent(raw[i], evs[i])
			}
		}
		seen = next
	}
}

func (a *App) printEvent(raw json.RawMessage, e event) {
	if a.json() {
		// One compact object per line (NDJSON) while following.
		var b bytes.Buffer
		if err := json.Compact(&b, raw); err == nil {
			fmt.Fprintln(a.Stdout, b.String())
		}
		return
	}
	a.eventRow(e)
}

// The URI, of unbounded length, comes last so that columns stay aligned.
const eventFmt = "%-19s  %-4s  %-15s  %-2s  %-7s  %-6s  %-8s  %-30s  %s\n"

func (a *App) eventHeader() {
	fmt.Fprintf(a.Stdout, eventFmt, "TIME", "SITE", "CLIENT", "CC", "METHOD", "STATUS", "ACTION", "KIND / RULES", "HOST + URI")
}

func (a *App) eventRow(e event) {
	rules := make([]int, len(e.Rules))
	for i, r := range e.Rules {
		rules[i] = r.ID
	}
	kind := cell(e.Kind)
	if len(rules) > 0 {
		kind += " " + cell(rules)
	}
	fmt.Fprintf(a.Stdout, eventFmt, fmtTime(e.Time), strconv.Itoa(e.SiteID), cell(e.ClientIP), cell(e.Country),
		cell(e.Method), strconv.Itoa(e.Status), cell(e.Action), truncate(kind, 30), cell(truncate(e.Host+e.URI, 100)))
}
