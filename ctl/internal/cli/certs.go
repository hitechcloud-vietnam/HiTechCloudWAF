package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type cert struct {
	ID       int       `json:"id"`
	Domains  []string  `json:"domains"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`
	Updated  time.Time `json:"updated_at"`
}

const certsUsage = "list | add --crt FILE --key FILE [--domains a,b] | delete ID..."

func (a *App) cmdCerts(ctx context.Context, args []string) error {
	return a.sub(ctx, "certs", args, map[string]func(context.Context, []string) error{
		"list":   a.certsList,
		"ls":     a.certsList,
		"add":    a.certsAdd,
		"delete": a.certsDelete,
		"rm":     a.certsDelete,
	}, certsUsage)
}

// redactKey hides the private key of a raw certificate object.
func redactKey(raw json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return raw
	}
	if k, ok := m["key"]; ok && string(k) != `""` && string(k) != "null" {
		m["key"] = json.RawMessage(`"<redacted>"`)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return b
}

func (a *App) certsList(ctx context.Context, args []string) error {
	fs := a.flags("certs list", "")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	var l list[json.RawMessage]
	if err := c.do(ctx, http.MethodGet, "/api/open/cert", nil, nil, &l); err != nil {
		return err
	}
	if a.json() {
		// Private keys are never printed; "hcwctl backup" exports them.
		for i := range l.Data {
			l.Data[i] = redactKey(l.Data[i])
		}
		return a.printJSON(rawArray(l.Data))
	}
	t := newTable(a.Stdout, "ID", "DOMAINS", "ISSUER", "NOT AFTER", "DAYS LEFT")
	now := time.Now()
	for _, raw := range l.Data {
		var ct cert
		if err := json.Unmarshal(raw, &ct); err != nil {
			return err
		}
		days := int(ct.NotAfter.Sub(now).Hours() / 24)
		left := fmt.Sprint(days)
		if ct.NotAfter.Before(now) {
			left = "EXPIRED"
		}
		t.row(ct.ID, ct.Domains, ct.Issuer, ct.NotAfter, left)
	}
	return t.flush()
}

func (a *App) certsAdd(ctx context.Context, args []string) error {
	fs := a.flags("certs add", "--crt FILE --key FILE [--domains a,b]")
	crtFile := fs.String("crt", "", "certificate chain (PEM)")
	keyFile := fs.String("key", "", "private key (PEM)")
	domains := fs.String("domains", "", "comma-separated domains (default: from the certificate)")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	if *crtFile == "" || *keyFile == "" {
		return usagef("certs add needs --crt FILE and --key FILE")
	}
	crt, err := os.ReadFile(*crtFile)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	body := map[string]any{"crt": string(crt), "key": string(key)}
	if *domains != "" {
		var ds []string
		for _, d := range strings.Split(*domains, ",") {
			if d = strings.TrimSpace(d); d != "" {
				ds = append(ds, d)
			}
		}
		body["domains"] = ds
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	var res json.RawMessage
	if err := c.do(ctx, http.MethodPost, "/api/open/cert", nil, body, &res); err != nil {
		return err
	}
	if a.json() {
		return a.printJSON(redactKey(res))
	}
	var ct cert
	if err := json.Unmarshal(res, &ct); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Certificate %d added: %s, issuer %s, valid until %s.\n", ct.ID, cell(ct.Domains), cell(ct.Issuer), cell(ct.NotAfter))
	return nil
}

func (a *App) certsDelete(ctx context.Context, args []string) error {
	fs := a.flags("certs delete", "ID...")
	pos, err := a.parse(fs, args, 1, -1)
	if err != nil {
		return err
	}
	ids, err := parseIDs(pos, "certificate")
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	if err := c.do(ctx, http.MethodDelete, "/api/open/cert", nil, map[string][]int{"ids": ids}, nil); err != nil {
		return err
	}
	if a.json() {
		return a.printJSON(map[string]any{"deleted": ids})
	}
	fmt.Fprintf(a.Stdout, "Deleted certificate(s) %s.\n", cell(ids))
	return nil
}
