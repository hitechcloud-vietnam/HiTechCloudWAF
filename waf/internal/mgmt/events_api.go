package mgmt

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/audit"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/store"
)

const (
	maxFilterText = 256
	topDefault    = 20
	topMax        = 100
)

// registerEventRoutes adds the security event listing, export, aggregation
// and the "deny this address" action used from the event view.
func (a *API) registerEventRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/open/events", a.listEvents)
	mux.HandleFunc("GET /api/open/events/export", a.exportEvents)
	mux.HandleFunc("GET /api/open/events/top", a.topEvents)
	mux.HandleFunc("POST /api/open/site/ip-deny", a.write(a.denyIP))
}

// eventFilter reads the filter query parameters shared by the event routes.
func eventFilter(q url.Values, now time.Time) (events.Filter, error) {
	var f events.Filter
	if s := strings.TrimSpace(q.Get("site_id")); s != "" {
		id, err := strconv.Atoi(s)
		if err != nil || id < 0 {
			return f, fmt.Errorf("invalid site_id %q", s)
		}
		f.SiteID = id
	}
	f.Kinds = csvParam(q.Get("kind"))
	f.Actions = csvParam(q.Get("action"))
	for _, c := range csvParam(q.Get("country")) {
		f.Countries = append(f.Countries, strings.ToUpper(c))
	}
	if s := strings.TrimSpace(q.Get("rule")); s != "" {
		id, err := strconv.Atoi(s)
		if err != nil || id <= 0 {
			return f, fmt.Errorf("invalid rule %q", s)
		}
		f.RuleID = id
	}
	var err error
	if f.IP, err = events.ParseIPFilter(q.Get("ip")); err != nil {
		return f, err
	}
	f.Text = strings.TrimSpace(q.Get("q"))
	if len(f.Text) > maxFilterText {
		return f, fmt.Errorf("q is longer than %d bytes", maxFilterText)
	}
	if f.Since, err = events.ParseTime(q.Get("since"), now); err != nil {
		return f, fmt.Errorf("since: %w", err)
	}
	if f.Until, err = events.ParseTime(q.Get("until"), now); err != nil {
		return f, fmt.Errorf("until: %w", err)
	}
	if !f.Since.IsZero() && !f.Until.IsZero() && f.Until.Before(f.Since) {
		return f, errors.New("until is before since")
	}
	return f, nil
}

// csvParam splits "a,b" into lower-case values; empty means "any".
func csvParam(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (a *API) listEvents(w http.ResponseWriter, r *http.Request) {
	f, err := eventFilter(r.URL.Query(), time.Now())
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid", err)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	ev := a.Events.Query(f, limit)
	ok(w, list[events.Event]{Data: ev, Total: len(ev)})
}

func (a *API) topEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f, err := eventFilter(q, time.Now())
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid", err)
		return
	}
	n, _ := strconv.Atoi(q.Get("limit"))
	if n <= 0 || n > topMax {
		n = topDefault
	}
	by := strings.ToLower(strings.TrimSpace(q.Get("by")))
	if by == "" {
		by = "ip"
	}
	items, total, err := a.Events.Top(f, by, n)
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid", err)
		return
	}
	ok(w, map[string]any{"by": by, "total": total, "items": items})
}

// csvColumns is the header of the CSV export.
var csvColumns = []string{"time", "id", "site_id", "site", "host", "client_ip", "country", "method", "uri",
	"user_agent", "kind", "action", "status", "feed", "rule_ids", "rule_msgs", "tags"}

// csvCell neutralises spreadsheet formulas: a cell that starts with = + - @
// (or a tab/CR/LF, which some spreadsheets strip before parsing) is prefixed
// with a single quote so it is shown as text. Quoting of commas, quotes and
// newlines is left to encoding/csv.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r\n", rune(s[0])) {
		return "'" + s
	}
	return s
}

func (a *API) exportEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f, err := eventFilter(q, time.Now())
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid", err)
		return
	}
	format := strings.ToLower(strings.TrimSpace(q.Get("format")))
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		fail(w, http.StatusBadRequest, "invalid", errors.New("format must be csv or json"))
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit < 0 {
		limit = 0 // every retained event
	}
	ev := a.Events.Query(f, limit)
	if a.Audit != nil { // exports carry client data: record who took them
		detail, _ := json.Marshal(map[string]any{"format": format, "events": len(ev), "query": r.URL.RawQuery})
		a.Audit.Add(audit.Entry{Time: time.Now().UTC(), User: callerOf(r).name, IP: clientHost(r),
			Action: "GET /api/open/events/export", Status: http.StatusOK, Detail: detail})
	}
	name := "hcw-waf-events-" + time.Now().UTC().Format("20060102-150405") + "." + format
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ev)
		return
	}
	names := map[int]string{}
	for _, s := range a.Store.Sites() {
		names[s.ID] = s.Name
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	cw := csv.NewWriter(w)
	_ = cw.Write(csvColumns)
	for _, e := range ev {
		ids := make([]string, 0, len(e.Rules))
		msgs := make([]string, 0, len(e.Rules))
		for _, rl := range e.Rules {
			ids = append(ids, strconv.Itoa(rl.ID))
			msgs = append(msgs, rl.Msg)
		}
		row := []string{e.Time.UTC().Format(time.RFC3339Nano), e.ID, strconv.Itoa(e.SiteID), names[e.SiteID], e.Host,
			e.ClientIP, e.Country, e.Method, e.URI, e.UA, e.Kind, e.Action, strconv.Itoa(e.Status), e.Feed,
			strings.Join(ids, " "), strings.Join(msgs, " | "), strings.Join(e.Tags, " ")}
		for i := range row {
			row[i] = csvCell(row[i])
		}
		if err := cw.Write(row); err != nil {
			return
		}
	}
	cw.Flush()
}

// denyIP adds an address or prefix to the deny list of the given sites
// (every site when site_ids is empty) in one configuration change.
func (a *API) denyIP(r *http.Request) (any, error) {
	var in struct {
		IP      string `json:"ip"`
		SiteIDs []int  `json:"site_ids"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	n, err := model.ParseCIDR(in.IP)
	if err != nil {
		return nil, err
	}
	if ones, _ := n.Mask.Size(); ones == 0 {
		return nil, errors.New("refusing to deny every address")
	}
	cidr := n.String()
	all := a.Store.Sites()
	byID := make(map[int]model.Site, len(all))
	for _, s := range all {
		byID[s.ID] = s
	}
	targets := in.SiteIDs
	if len(targets) == 0 {
		for _, s := range all {
			targets = append(targets, s.ID)
		}
	}
	if len(targets) == 0 {
		return nil, errors.New("there are no sites")
	}
	for _, id := range targets {
		if _, ok := byID[id]; !ok {
			return nil, fmt.Errorf("site %d: %w", id, store.ErrNotFound)
		}
	}
	added, already := []int{}, []int{}
	for _, id := range targets {
		s, err := cloneSite(byID[id])
		if err != nil {
			return nil, err
		}
		if denies(s.IPDeny, cidr) {
			already = append(already, id)
			continue
		}
		s.IPDeny = append(s.IPDeny, cidr)
		if _, err := a.Store.UpdateSite(s); err != nil {
			return nil, fmt.Errorf("site %d: %w", id, err)
		}
		added = append(added, id)
	}
	a.Log.Info("address denied", "ip", cidr, "sites", added, "by", callerOf(r).name)
	return map[string]any{"ip": cidr, "added": added, "unchanged": already}, nil
}

// denies reports whether list already holds exactly cidr.
func denies(list []string, cidr string) bool {
	for _, v := range list {
		if n, err := model.ParseCIDR(v); err == nil && n.String() == cidr {
			return true
		}
	}
	return false
}

// cloneSite deep-copies a site so normalising it cannot touch the store's
// copy (Store.Sites shares slices with the stored value).
func cloneSite(s model.Site) (model.Site, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return model.Site{}, err
	}
	var c model.Site
	err = json.Unmarshal(b, &c)
	return c, err
}
