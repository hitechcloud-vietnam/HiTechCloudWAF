package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type me struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Account  bool   `json:"account"`
}

func (a *App) cmdLogin(ctx context.Context, args []string) error {
	fs := a.flags("login", "--url https://HOST:9443 [--user USER | --token-file FILE] [--ca FILE | --insecure] [--profile NAME]")
	rawURL := fs.String("url", "", "management API URL, e.g. https://waf.example.com:9443 (default $HCWCTL_URL)")
	user := fs.String("user", "", "console user name (password from $HCWCTL_PASSWORD or stdin)")
	tokenFile := fs.String("token-file", "", "file holding the node API token (default $HCWCTL_TOKEN or stdin)")
	caFile := fs.String("ca", "", "trust only this CA / certificate file (PEM) for the API")
	insecure := fs.Bool("insecure", false, "skip certificate verification (loopback hosts only)")
	otp := fs.String("otp", "", "TOTP code, if the account has two-factor authentication (default $HCWCTL_OTP or stdin)")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	if *rawURL == "" {
		*rawURL = a.Getenv("HCWCTL_URL")
	}
	if *rawURL == "" {
		return usagef("login needs --url https://HOST:9443")
	}
	if *user != "" && *tokenFile != "" {
		return usagef("use either --user or --token-file, not both")
	}
	u, err := normalizeURL(*rawURL)
	if err != nil {
		return usagef("%v", err)
	}
	p := &Profile{URL: u.String(), Insecure: *insecure}
	if *caFile != "" {
		if p.CAFile, err = filepath.Abs(*caFile); err != nil {
			return err
		}
	}
	c, err := newClient(p)
	if err != nil {
		return err
	}

	if *user != "" {
		pw := a.Getenv("HCWCTL_PASSWORD")
		if pw == "" {
			if pw, err = a.readSecret(ctx, "Password for "+*user+": "); err != nil {
				return fmt.Errorf("password: %w", err)
			}
		}
		code := *otp
		if code == "" {
			code = a.Getenv("HCWCTL_OTP")
		}
		var res struct {
			Token    string    `json:"token"`
			Username string    `json:"username"`
			Role     string    `json:"role"`
			Expires  time.Time `json:"expires"`
		}
		in := map[string]string{"username": *user, "password": pw, "otp": code}
		err = c.do(ctx, http.MethodPost, "/api/auth/login", nil, in, &res)
		var ae *APIError
		if errors.As(err, &ae) && ae.Code == "otp_required" && code == "" {
			if in["otp"], err = a.readLine(ctx, "Two-factor code: "); err != nil {
				return fmt.Errorf("OTP: %w", err)
			}
			err = c.do(ctx, http.MethodPost, "/api/auth/login", nil, in, &res)
		}
		if err != nil {
			return fmt.Errorf("login failed: %w", err)
		}
		if res.Token == "" {
			return errors.New("login failed: the server returned no session")
		}
		p.Session, p.User, p.Role = res.Token, res.Username, res.Role
		if !res.Expires.IsZero() {
			p.Expires = res.Expires.UTC().Format(time.RFC3339)
		}
	} else {
		var tok string
		switch {
		case *tokenFile != "":
			b, err := os.ReadFile(*tokenFile)
			if err != nil {
				return fmt.Errorf("token file: %w", err)
			}
			tok = strings.TrimSpace(string(b))
		case a.Getenv("HCWCTL_TOKEN") != "":
			tok = a.Getenv("HCWCTL_TOKEN")
		default:
			if tok, err = a.readSecret(ctx, "API token: "); err != nil {
				return fmt.Errorf("token: %w", err)
			}
			tok = strings.TrimSpace(tok)
		}
		if tok == "" {
			return errors.New("the API token is empty")
		}
		p.Token = tok
	}

	// Check the credentials before saving them.
	c, err = newClient(p)
	if err != nil {
		return err
	}
	var who me
	if err := c.do(ctx, http.MethodGet, "/api/open/me", nil, nil, &who); err != nil {
		var ae *APIError
		if errors.As(err, &ae) {
			return fmt.Errorf("credentials rejected: %w", err)
		}
		return err
	}
	p.User, p.Role = who.Username, who.Role

	cfg, path, err := a.loadConfig()
	if err != nil {
		return err
	}
	name := a.profile
	if name == "" {
		name = a.Getenv("HCWCTL_PROFILE")
	}
	if name == "" {
		name = "default"
	}
	cfg.Profiles[name] = p
	cfg.Current = name
	if err := saveConfig(path, cfg); err != nil {
		return fmt.Errorf("saving %s: %w", path, err)
	}
	if a.json() {
		return a.printJSON(map[string]any{"profile": name, "url": p.URL, "user": p.User, "role": p.Role, "auth": p.authKind(), "config": path})
	}
	fmt.Fprintf(a.Stdout, "Logged in to %s as %s (%s, %s). Profile %q saved in %s.\n", p.URL, cell(p.User), cell(p.Role), p.authKind(), name, path)
	return nil
}

func (a *App) cmdLogout(ctx context.Context, args []string) error {
	fs := a.flags("logout", "[--profile NAME]")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	cfg, path, err := a.loadConfig()
	if err != nil {
		return err
	}
	name := a.profileName(cfg)
	p, ok := cfg.Profiles[name]
	if !ok {
		return fmt.Errorf("no profile %q (profiles: %s)", name, profileList(cfg))
	}
	if p.Session != "" {
		// End the session on the server too; ignore failures (expired, offline).
		if c, err := newClient(p); err == nil {
			_ = c.do(ctx, http.MethodPost, "/api/auth/logout", nil, nil, nil)
		}
	}
	delete(cfg.Profiles, name)
	if cfg.Current == name {
		cfg.Current = ""
	}
	if err := saveConfig(path, cfg); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Profile %q removed.\n", name)
	return nil
}

func (a *App) cmdProfiles(_ context.Context, args []string) error {
	fs := a.flags("profiles", "[list | use NAME]")
	pos, err := a.parse(fs, args, 0, 2)
	if err != nil {
		return err
	}
	cfg, path, err := a.loadConfig()
	if err != nil {
		return err
	}
	if len(pos) > 0 && pos[0] == "use" {
		if len(pos) != 2 {
			return usagef("usage: hcwctl profiles use NAME")
		}
		if _, ok := cfg.Profiles[pos[1]]; !ok {
			return fmt.Errorf("no profile %q (profiles: %s)", pos[1], profileList(cfg))
		}
		cfg.Current = pos[1]
		if err := saveConfig(path, cfg); err != nil {
			return err
		}
		fmt.Fprintf(a.Stdout, "Current profile is now %q.\n", pos[1])
		return nil
	}
	if len(pos) > 0 && pos[0] != "list" || len(pos) > 1 {
		return usagef("usage: hcwctl profiles [list | use NAME]")
	}
	names := make([]string, 0, len(cfg.Profiles))
	for n := range cfg.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	if a.json() {
		out := []map[string]any{}
		for _, n := range names {
			p := cfg.Profiles[n]
			out = append(out, map[string]any{"name": n, "current": n == cfg.Current, "url": p.URL, "auth": p.authKind(),
				"user": p.User, "role": p.Role, "ca_file": p.CAFile, "insecure": p.Insecure})
		}
		return a.printJSON(out)
	}
	t := newTable(a.Stdout, "CURRENT", "NAME", "URL", "AUTH", "USER", "ROLE", "TLS")
	for _, n := range names {
		p := cfg.Profiles[n]
		cur := " "
		if n == cfg.Current {
			cur = "*"
		}
		tlsMode := "system roots"
		switch {
		case p.CAFile != "":
			tlsMode = "ca " + p.CAFile
		case p.Insecure:
			tlsMode = "insecure (loopback)"
		}
		t.row(cur, n, p.URL, p.authKind(), p.User, p.Role, tlsMode)
	}
	return t.flush()
}
