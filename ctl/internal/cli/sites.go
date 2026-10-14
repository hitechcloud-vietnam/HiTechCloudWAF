package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// site holds the fields hcwctl displays. Changes are made on the raw JSON so
// that fields unknown to this client survive a round trip.
type site struct {
	ID               int      `json:"id"`
	Name             string   `json:"name"`
	ServerNames      []string `json:"server_names"`
	Ports            []string `json:"ports"`
	Upstreams        []string `json:"upstreams"`
	CertID           int      `json:"cert_id"`
	Mode             string   `json:"mode"`
	Paranoia         int      `json:"paranoia"`
	AnomalyThreshold int      `json:"anomaly_threshold"`
	DisabledRules    []int    `json:"disabled_rules"`
	RateLimit        struct {
		Requests  int `json:"requests"`
		WindowSec int `json:"window_sec"`
		BlockSec  int `json:"block_sec"`
	} `json:"rate_limit"`
	Bot struct {
		Enabled bool `json:"enabled"`
	} `json:"bot_challenge"`
	Auth struct {
		Enabled bool `json:"enabled"`
	} `json:"auth"`
	Health struct {
		Path string `json:"path"`
	} `json:"health_check"`
	Rules         []json.RawMessage `json:"rules"`
	IPAllow       []string          `json:"ip_allow"`
	IPDeny        []string          `json:"ip_deny"`
	CountryAllow  []string          `json:"country_allow"`
	CountryDeny   []string          `json:"country_deny"`
	AutoTLS       bool              `json:"auto_tls"`
	RedirectHTTPS bool              `json:"redirect_https"`
	HSTS          bool              `json:"hsts"`
	Comment       string            `json:"comment"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

const sitesUsage = "list | get ID | create -f FILE | update [ID] -f FILE | delete ID... | set-mode ID block|monitor|off | deny-ip ID CIDR... | allow-rule ID RULE... | disable-rule ID RULE..."

func (a *App) cmdSites(ctx context.Context, args []string) error {
	return a.sub(ctx, "sites", args, map[string]func(context.Context, []string) error{
		"list":         a.sitesList,
		"ls":           a.sitesList,
		"get":          a.sitesGet,
		"create":       a.sitesCreate,
		"update":       a.sitesUpdate,
		"delete":       a.sitesDelete,
		"rm":           a.sitesDelete,
		"set-mode":     a.sitesSetMode,
		"deny-ip":      a.sitesDenyIP,
		"allow-rule":   a.sitesAllowRule,
		"disable-rule": a.sitesDisableRule,
	}, sitesUsage)
}

// fetchSites returns the raw sites.
func (c *client) fetchSites(ctx context.Context) ([]json.RawMessage, error) {
	var l list[json.RawMessage]
	if err := c.do(ctx, http.MethodGet, "/api/open/site", nil, nil, &l); err != nil {
		return nil, err
	}
	return l.Data, nil
}

func (c *client) fetchSite(ctx context.Context, id int) (json.RawMessage, error) {
	all, err := c.fetchSites(ctx)
	if err != nil {
		return nil, err
	}
	for _, raw := range all {
		var s struct {
			ID int `json:"id"`
		}
		if json.Unmarshal(raw, &s) == nil && s.ID == id {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("site %d not found", id)
}

// siteNames maps site IDs to names (empty when sites cannot be read).
func (c *client) siteNames(ctx context.Context) map[int]string {
	out := map[int]string{}
	all, err := c.fetchSites(ctx)
	if err != nil {
		return out
	}
	for _, raw := range all {
		var s site
		if json.Unmarshal(raw, &s) == nil {
			out[s.ID] = s.Name
		}
	}
	return out
}

func parseID(s, what string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid %s ID %q (a positive number)", what, s)
	}
	return n, nil
}

func parseIDs(args []string, what string) ([]int, error) {
	ids := make([]int, 0, len(args))
	for _, s := range args {
		n, err := parseID(s, what)
		if err != nil {
			return nil, err
		}
		ids = append(ids, n)
	}
	return ids, nil
}

func (a *App) sitesList(ctx context.Context, args []string) error {
	fs := a.flags("sites list", "")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	raw, err := c.fetchSites(ctx)
	if err != nil {
		return err
	}
	if a.json() {
		return a.printJSON(rawArray(raw))
	}
	t := newTable(a.Stdout, "ID", "NAME", "SERVER NAMES", "PORTS", "UPSTREAMS", "MODE", "CERT", "UPDATED")
	for _, r := range raw {
		var s site
		if err := json.Unmarshal(r, &s); err != nil {
			return err
		}
		cert := "-"
		switch {
		case s.AutoTLS:
			cert = "auto"
		case s.CertID > 0:
			cert = strconv.Itoa(s.CertID)
		}
		t.row(s.ID, s.Name, s.ServerNames, s.Ports, s.Upstreams, s.Mode, cert, s.UpdatedAt)
	}
	return t.flush()
}

func rawArray(items []json.RawMessage) json.RawMessage {
	if items == nil {
		items = []json.RawMessage{}
	}
	b, _ := json.Marshal(items)
	return b
}

func (a *App) sitesGet(ctx context.Context, args []string) error {
	fs := a.flags("sites get", "ID")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	id, err := parseID(pos[0], "site")
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	raw, err := c.fetchSite(ctx, id)
	if err != nil {
		return err
	}
	if a.json() {
		return a.printJSON(raw)
	}
	var s site
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	return a.printSite(s)
}

func (a *App) printSite(s site) error {
	t := newTable(a.Stdout, "FIELD", "VALUE")
	rl := "off"
	if s.RateLimit.Requests > 0 {
		rl = fmt.Sprintf("%d req / %ds, block %ds", s.RateLimit.Requests, s.RateLimit.WindowSec, s.RateLimit.BlockSec)
	}
	t.row("id", s.ID)
	t.row("name", s.Name)
	t.row("server_names", s.ServerNames)
	t.row("ports", s.Ports)
	t.row("upstreams", s.Upstreams)
	t.row("mode", s.Mode)
	t.row("cert_id", s.CertID)
	t.row("auto_tls", s.AutoTLS)
	t.row("redirect_https", s.RedirectHTTPS)
	t.row("hsts", s.HSTS)
	t.row("paranoia", s.Paranoia)
	t.row("anomaly_threshold", s.AnomalyThreshold)
	t.row("disabled_rules", s.DisabledRules)
	t.row("rate_limit", rl)
	t.row("bot_challenge", s.Bot.Enabled)
	t.row("auth", s.Auth.Enabled)
	t.row("health_check", s.Health.Path)
	t.row("path rules", len(s.Rules))
	t.row("ip_allow", s.IPAllow)
	t.row("ip_deny", s.IPDeny)
	t.row("country_allow", s.CountryAllow)
	t.row("country_deny", s.CountryDeny)
	t.row("comment", s.Comment)
	t.row("created_at", s.CreatedAt)
	t.row("updated_at", s.UpdatedAt)
	return t.flush()
}

// readJSONObject reads a JSON object from path ("-" = stdin).
func (a *App) readJSONObject(path string) (map[string]json.RawMessage, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(io.LimitReader(a.reader(), 64<<20))
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&m); err != nil || m == nil {
		if err == nil {
			err = errors.New("not a JSON object")
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

func (a *App) sitesCreate(ctx context.Context, args []string) error {
	fs := a.flags("sites create", "-f site.json")
	file := fs.String("f", "", "site JSON file (- for stdin)")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	if *file == "" {
		return usagef("sites create needs -f FILE")
	}
	m, err := a.readJSONObject(*file)
	if err != nil {
		return err
	}
	delete(m, "id")
	c, err := a.client()
	if err != nil {
		return err
	}
	return a.writeSite(ctx, c, http.MethodPost, m, "created")
}

func (a *App) sitesUpdate(ctx context.Context, args []string) error {
	fs := a.flags("sites update", "[ID] -f site.json")
	file := fs.String("f", "", "complete site JSON file (- for stdin); it replaces the site")
	pos, err := a.parse(fs, args, 0, 1)
	if err != nil {
		return err
	}
	if *file == "" {
		return usagef("sites update needs -f FILE")
	}
	m, err := a.readJSONObject(*file)
	if err != nil {
		return err
	}
	if len(pos) == 1 {
		id, err := parseID(pos[0], "site")
		if err != nil {
			return err
		}
		m["id"] = json.RawMessage(strconv.Itoa(id))
	}
	var id int
	if err := json.Unmarshal(m["id"], &id); err != nil || id <= 0 {
		return errors.New(`sites update needs the site ID: an "id" field in the file or hcwctl sites update ID -f FILE`)
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	return a.writeSite(ctx, c, http.MethodPut, m, "updated")
}

func (a *App) writeSite(ctx context.Context, c *client, method string, m map[string]json.RawMessage, verb string) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var res json.RawMessage
	if err := c.do(ctx, method, "/api/open/site", nil, json.RawMessage(body), &res); err != nil {
		return err
	}
	if a.json() {
		return a.printJSON(res)
	}
	var s site
	if err := json.Unmarshal(res, &s); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Site %d (%s) %s: mode %s, %s.\n", s.ID, cell(s.Name), verb, cell(s.Mode), cell(s.ServerNames))
	return nil
}

func (a *App) sitesDelete(ctx context.Context, args []string) error {
	fs := a.flags("sites delete", "ID...")
	pos, err := a.parse(fs, args, 1, -1)
	if err != nil {
		return err
	}
	ids, err := parseIDs(pos, "site")
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	if err := c.do(ctx, http.MethodDelete, "/api/open/site", nil, map[string][]int{"ids": ids}, nil); err != nil {
		return err
	}
	if a.json() {
		return a.printJSON(map[string]any{"deleted": ids})
	}
	fmt.Fprintf(a.Stdout, "Deleted site(s) %s.\n", cell(ids))
	return nil
}

// modifySite reads site id, lets f change its raw fields and saves it.
// f returns a description of the change, or "" when nothing changed.
func (a *App) modifySite(ctx context.Context, idArg string, f func(m map[string]json.RawMessage) (string, error)) error {
	id, err := parseID(idArg, "site")
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	raw, err := c.fetchSite(ctx, id)
	if err != nil {
		return err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	change, err := f(m)
	if err != nil {
		return err
	}
	if change == "" {
		if a.json() {
			return a.printJSON(raw)
		}
		fmt.Fprintf(a.Stdout, "Site %d: no change.\n", id)
		return nil
	}
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var res json.RawMessage
	if err := c.do(ctx, http.MethodPut, "/api/open/site", nil, json.RawMessage(body), &res); err != nil {
		return err
	}
	if a.json() {
		return a.printJSON(res)
	}
	fmt.Fprintf(a.Stdout, "Site %d: %s.\n", id, change)
	return nil
}

func getField[T any](m map[string]json.RawMessage, key string) (T, error) {
	var v T
	if r, ok := m[key]; ok && string(r) != "null" {
		if err := json.Unmarshal(r, &v); err != nil {
			return v, fmt.Errorf("site field %s: %w", key, err)
		}
	}
	return v, nil
}

func setField(m map[string]json.RawMessage, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	m[key] = b
	return nil
}

func (a *App) sitesSetMode(ctx context.Context, args []string) error {
	fs := a.flags("sites set-mode", "ID block|monitor|off")
	pos, err := a.parse(fs, args, 2, 2)
	if err != nil {
		return err
	}
	mode := strings.ToLower(pos[1])
	switch mode {
	case "block", "monitor", "off":
	default:
		return fmt.Errorf("invalid mode %q: use block, monitor or off", pos[1])
	}
	return a.modifySite(ctx, pos[0], func(m map[string]json.RawMessage) (string, error) {
		old, err := getField[string](m, "mode")
		if err != nil {
			return "", err
		}
		if old == mode {
			return "", nil
		}
		return "mode " + cell(old) + " -> " + mode, setField(m, "mode", mode)
	})
}

// normalizeCIDR matches the server's form: "1.2.3.4" -> "1.2.3.4/32".
func normalizeCIDR(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", fmt.Errorf("invalid IP/CIDR %q", s)
		}
		return p.Masked().String(), nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.Zone() != "" {
		return "", fmt.Errorf("invalid IP/CIDR %q", s)
	}
	ip = ip.Unmap()
	return netip.PrefixFrom(ip, ip.BitLen()).String(), nil
}

func (a *App) sitesDenyIP(ctx context.Context, args []string) error {
	fs := a.flags("sites deny-ip", "ID IP/CIDR...")
	pos, err := a.parse(fs, args, 2, -1)
	if err != nil {
		return err
	}
	var add []string
	for _, s := range pos[1:] {
		n, err := normalizeCIDR(s)
		if err != nil {
			return err
		}
		add = append(add, n)
	}
	return a.modifySite(ctx, pos[0], func(m map[string]json.RawMessage) (string, error) {
		deny, err := getField[[]string](m, "ip_deny")
		if err != nil {
			return "", err
		}
		var added []string
		for _, n := range add {
			if !slices.Contains(deny, n) {
				deny = append(deny, n)
				added = append(added, n)
			}
		}
		if len(added) == 0 {
			return "", nil
		}
		return "denied " + strings.Join(added, ", ") + fmt.Sprintf(" (ip_deny has %d entries)", len(deny)), setField(m, "ip_deny", deny)
	})
}

func parseRuleIDs(args []string) ([]int, error) {
	var out []int
	for _, s := range args {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid rule ID %q (a CRS rule number such as 942100)", s)
		}
		out = append(out, n)
	}
	return out, nil
}

func (a *App) sitesAllowRule(ctx context.Context, args []string) error {
	fs := a.flags("sites allow-rule", "ID RULE-ID...")
	pos, err := a.parse(fs, args, 2, -1)
	if err != nil {
		return err
	}
	rules, err := parseRuleIDs(pos[1:])
	if err != nil {
		return err
	}
	return a.modifySite(ctx, pos[0], func(m map[string]json.RawMessage) (string, error) {
		cur, err := getField[[]int](m, "disabled_rules")
		if err != nil {
			return "", err
		}
		var removed []int
		kept := []int{}
		for _, r := range cur {
			if slices.Contains(rules, r) {
				removed = append(removed, r)
			} else {
				kept = append(kept, r)
			}
		}
		if len(removed) == 0 {
			return "", nil
		}
		return "re-enabled rule(s) " + cell(removed), setField(m, "disabled_rules", kept)
	})
}

func (a *App) sitesDisableRule(ctx context.Context, args []string) error {
	fs := a.flags("sites disable-rule", "ID RULE-ID...")
	pos, err := a.parse(fs, args, 2, -1)
	if err != nil {
		return err
	}
	rules, err := parseRuleIDs(pos[1:])
	if err != nil {
		return err
	}
	return a.modifySite(ctx, pos[0], func(m map[string]json.RawMessage) (string, error) {
		cur, err := getField[[]int](m, "disabled_rules")
		if err != nil {
			return "", err
		}
		var added []int
		for _, r := range rules {
			if !slices.Contains(cur, r) {
				cur = append(cur, r)
				added = append(added, r)
			}
		}
		if len(added) == 0 {
			return "", nil
		}
		return "disabled rule(s) " + cell(added), setField(m, "disabled_rules", cur)
	})
}
