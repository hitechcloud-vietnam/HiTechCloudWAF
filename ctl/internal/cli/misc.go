package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type counters struct {
	Requests  uint64 `json:"requests"`
	Blocked   uint64 `json:"blocked"`
	Monitored uint64 `json:"monitored"`
	RateLimit uint64 `json:"rate_limited"`
	ACL       uint64 `json:"acl_blocked"`
	Bot       uint64 `json:"bot_failed"`
}

// sortedIDs returns the numeric keys of a JSON object keyed by site ID.
func sortedIDs[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, ea := strconv.Atoi(keys[i])
		b, eb := strconv.Atoi(keys[j])
		if ea != nil || eb != nil {
			return keys[i] < keys[j]
		}
		return a < b
	})
	return keys
}

func siteName(names map[int]string, key string) string {
	id, _ := strconv.Atoi(key)
	return names[id]
}

func (a *App) cmdStats(ctx context.Context, args []string) error {
	fs := a.flags("stats", "")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/api/open/stats", nil, nil, &raw); err != nil {
		return err
	}
	if a.json() {
		return a.printJSON(raw)
	}
	var stats map[string]counters
	if err := json.Unmarshal(raw, &stats); err != nil {
		return err
	}
	names := c.siteNames(ctx)
	t := newTable(a.Stdout, "SITE", "NAME", "REQUESTS", "BLOCKED", "MONITORED", "RATE LIMITED", "ACL", "BOT")
	var tot counters
	for _, k := range sortedIDs(stats) {
		s := stats[k]
		t.row(k, siteName(names, k), s.Requests, s.Blocked, s.Monitored, s.RateLimit, s.ACL, s.Bot)
		tot.Requests += s.Requests
		tot.Blocked += s.Blocked
		tot.Monitored += s.Monitored
		tot.RateLimit += s.RateLimit
		tot.ACL += s.ACL
		tot.Bot += s.Bot
	}
	t.row("all", "", tot.Requests, tot.Blocked, tot.Monitored, tot.RateLimit, tot.ACL, tot.Bot)
	return t.flush()
}

func (a *App) cmdUpstreams(ctx context.Context, args []string) error {
	fs := a.flags("upstreams", "")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/api/open/upstreams", nil, nil, &raw); err != nil {
		return err
	}
	if a.json() {
		return a.printJSON(raw)
	}
	var ups map[string][]struct {
		URL       string    `json:"url"`
		Healthy   bool      `json:"healthy"`
		Checked   bool      `json:"checked"`
		LastCheck time.Time `json:"last_check"`
		LastError string    `json:"last_error"`
	}
	if err := json.Unmarshal(raw, &ups); err != nil {
		return err
	}
	names := c.siteNames(ctx)
	t := newTable(a.Stdout, "SITE", "NAME", "UPSTREAM", "HEALTHY", "CHECKED", "LAST CHECK", "LAST ERROR")
	for _, k := range sortedIDs(ups) {
		for _, u := range ups[k] {
			t.row(k, siteName(names, k), u.URL, u.Healthy, u.Checked, u.LastCheck, u.LastError)
		}
	}
	return t.flush()
}

func (a *App) cmdAudit(ctx context.Context, args []string) error {
	fs := a.flags("audit", "[--limit N]")
	limit := fs.Int("limit", 50, "number of entries (1..2000)")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	if *limit < 1 || *limit > 2000 {
		return usagef("--limit must be 1..2000")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	var l list[json.RawMessage]
	if err := c.do(ctx, http.MethodGet, "/api/open/audit", url.Values{"limit": {strconv.Itoa(*limit)}}, nil, &l); err != nil {
		return err
	}
	if a.json() {
		return a.printJSON(rawArray(l.Data))
	}
	t := newTable(a.Stdout, "TIME", "USER", "IP", "STATUS", "ACTION")
	for i := len(l.Data) - 1; i >= 0; i-- { // oldest first
		var e struct {
			Time   time.Time `json:"time"`
			User   string    `json:"user"`
			IP     string    `json:"ip"`
			Action string    `json:"action"`
			Status int       `json:"status"`
		}
		if err := json.Unmarshal(l.Data[i], &e); err != nil {
			return err
		}
		t.row(e.Time, e.User, e.IP, e.Status, e.Action)
	}
	return t.flush()
}

const usersUsage = "list | add NAME [--role admin|viewer] | delete NAME..."

func (a *App) cmdUsers(ctx context.Context, args []string) error {
	return a.sub(ctx, "users", args, map[string]func(context.Context, []string) error{
		"list":   a.usersList,
		"ls":     a.usersList,
		"add":    a.usersAdd,
		"delete": a.usersDelete,
		"rm":     a.usersDelete,
	}, usersUsage)
}

func (a *App) usersList(ctx context.Context, args []string) error {
	fs := a.flags("users list", "")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	var l list[json.RawMessage]
	if err := c.do(ctx, http.MethodGet, "/api/open/users", nil, nil, &l); err != nil {
		return err
	}
	if a.json() {
		return a.printJSON(rawArray(l.Data))
	}
	t := newTable(a.Stdout, "USERNAME", "ROLE", "2FA", "CREATED", "LAST LOGIN")
	for _, raw := range l.Data {
		var u struct {
			Username  string    `json:"username"`
			Role      string    `json:"role"`
			TOTP      bool      `json:"totp"`
			CreatedAt time.Time `json:"created_at"`
			LastLogin time.Time `json:"last_login"`
		}
		if err := json.Unmarshal(raw, &u); err != nil {
			return err
		}
		t.row(u.Username, u.Role, u.TOTP, u.CreatedAt, u.LastLogin)
	}
	return t.flush()
}

func (a *App) usersAdd(ctx context.Context, args []string) error {
	fs := a.flags("users add", "NAME [--role admin|viewer]")
	role := fs.String("role", "viewer", "admin or viewer")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	if *role != "admin" && *role != "viewer" {
		return fmt.Errorf("invalid role %q: use admin or viewer", *role)
	}
	pw := a.Getenv("HCWCTL_NEW_PASSWORD")
	if pw == "" {
		if pw, err = a.readSecret(ctx, "Password for new user "+pos[0]+": "); err != nil {
			return fmt.Errorf("password: %w", err)
		}
		if a.stdinTerminal() != nil {
			again, err := a.readSecret(ctx, "Repeat the password: ")
			if err != nil {
				return err
			}
			if again != pw {
				return errors.New("the passwords do not match")
			}
		}
	}
	if pw == "" {
		return errors.New("the password is empty")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	body := map[string]string{"username": pos[0], "password": pw, "role": *role}
	if err := c.do(ctx, http.MethodPost, "/api/open/users", nil, body, nil); err != nil {
		return err
	}
	if a.json() {
		return a.printJSON(map[string]string{"username": pos[0], "role": *role})
	}
	fmt.Fprintf(a.Stdout, "User %s added (%s).\n", cell(pos[0]), *role)
	return nil
}

func (a *App) usersDelete(ctx context.Context, args []string) error {
	fs := a.flags("users delete", "NAME...")
	pos, err := a.parse(fs, args, 1, -1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	if err := c.do(ctx, http.MethodDelete, "/api/open/users", nil, map[string][]string{"usernames": pos}, nil); err != nil {
		return err
	}
	if a.json() {
		return a.printJSON(map[string]any{"deleted": pos})
	}
	fmt.Fprintf(a.Stdout, "Deleted user(s) %s.\n", cell(pos))
	return nil
}

type backupSummary struct {
	Version    int               `json:"version"`
	ExportedAt time.Time         `json:"exported_at"`
	Sites      []json.RawMessage `json:"sites"`
	Certs      []json.RawMessage `json:"certs"`
}

func (a *App) cmdBackup(ctx context.Context, args []string) error {
	fs := a.flags("backup", "[--file FILE]  (or: hcwctl backup > backup.json)")
	file := fs.String("file", "", "write to FILE (mode 0600) instead of stdout")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/api/open/backup", nil, nil, &raw); err != nil {
		return err
	}
	var sum backupSummary
	if err := json.Unmarshal(raw, &sum); err != nil {
		return fmt.Errorf("unexpected backup: %w", err)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return err
	}
	buf.WriteByte('\n')
	where := "stdout"
	if *file != "" {
		if err := os.WriteFile(*file, buf.Bytes(), 0o600); err != nil {
			return err
		}
		if err := os.Chmod(*file, 0o600); err != nil {
			return err
		}
		where = *file
	} else if _, err := a.Stdout.Write(buf.Bytes()); err != nil {
		return err
	}
	fmt.Fprintf(a.Stderr, "Backup of %d site(s) and %d certificate(s) written to %s. It contains private keys: keep it safe.\n",
		len(sum.Sites), len(sum.Certs), where)
	return nil
}

func (a *App) cmdRestore(ctx context.Context, args []string) error {
	fs := a.flags("restore", "FILE [--yes]")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	fs.BoolVar(yes, "y", false, "shorthand for --yes")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	var b []byte
	if pos[0] == "-" {
		if !*yes {
			return usagef("restoring from stdin needs --yes (stdin cannot also answer the confirmation)")
		}
		b, err = io.ReadAll(io.LimitReader(a.reader(), 256<<20))
	} else {
		b, err = os.ReadFile(pos[0])
	}
	if err != nil {
		return err
	}
	// Accept the API envelope too ({"data": {...}}, e.g. saved with curl).
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return fmt.Errorf("%s: not a JSON backup: %w", pos[0], err)
	}
	if _, ok := probe["sites"]; !ok {
		if d, ok := probe["data"]; ok {
			b = d
		}
	}
	var sum backupSummary
	if err := json.Unmarshal(b, &sum); err != nil || sum.Sites == nil && sum.Certs == nil {
		return fmt.Errorf("%s: not a HiTechCloud WAF backup (no sites or certs)", pos[0])
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	if !*yes {
		ans, err := a.readLine(ctx, fmt.Sprintf("This REPLACES all sites and certificates on %s with %d site(s) and %d certificate(s) from %s.\nType \"yes\" to continue: ",
			c.base.String(), len(sum.Sites), len(sum.Certs), pos[0]))
		if err != nil {
			return fmt.Errorf("confirmation: %w (use --yes in scripts)", err)
		}
		if strings.ToLower(strings.TrimSpace(ans)) != "yes" {
			return errors.New("restore aborted")
		}
	}
	var res map[string]int
	if err := c.do(ctx, http.MethodPost, "/api/open/restore", nil, json.RawMessage(b), &res); err != nil {
		return err
	}
	if a.json() {
		return a.printJSON(res)
	}
	fmt.Fprintf(a.Stdout, "Restored %d site(s) and %d certificate(s).\n", res["sites"], res["certs"])
	return nil
}

func (a *App) cmdAlerts(ctx context.Context, args []string) error {
	return a.sub(ctx, "alerts", args, map[string]func(context.Context, []string) error{
		"test": func(ctx context.Context, args []string) error {
			fs := a.flags("alerts test", "")
			if _, err := a.parse(fs, args, 0, 0); err != nil {
				return err
			}
			c, err := a.client()
			if err != nil {
				return err
			}
			var res string
			if err := c.do(ctx, http.MethodPost, "/api/open/alerts/test", nil, nil, &res); err != nil {
				return err
			}
			if a.json() {
				return a.printJSON(map[string]string{"result": res})
			}
			fmt.Fprintln(a.Stdout, "Test alert sent.")
			return nil
		},
	}, "test")
}

func (a *App) cmdVersion(ctx context.Context, args []string) error {
	fs := a.flags("version", "[--client]")
	clientOnly := fs.Bool("client", false, "do not query the server")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	cl := map[string]string{"version": Version, "go": runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH}
	out := map[string]any{"client": cl}
	var srvErr error
	if !*clientOnly {
		if p, _, err := a.resolve(); err == nil {
			c, err := newClient(p)
			if err == nil {
				var info map[string]any
				if err = c.do(ctx, http.MethodGet, "/api/open/info", nil, nil, &info); err == nil {
					info["url"] = c.base.String()
					out["server"] = info
				}
			}
			srvErr = err
		}
	}
	if a.json() {
		if err := a.printJSON(out); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(a.Stdout, "hcwctl %s (%s, %s)\n", Version, cl["go"], cl["platform"])
		if s, ok := out["server"].(map[string]any); ok {
			fmt.Fprintf(a.Stdout, "server %s at %s (%v sites, %v certificates, started %v)\n",
				cell(fmt.Sprint(s["version"])), s["url"], s["sites"], s["certs"], cell(fmt.Sprint(s["started_at"])))
		}
	}
	if srvErr != nil {
		return fmt.Errorf("server: %w", srvErr)
	}
	return nil
}
