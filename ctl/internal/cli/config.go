package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// Config is the profile file.
type Config struct {
	Current  string              `json:"current,omitempty"`
	Profiles map[string]*Profile `json:"profiles"`
}

// Profile is one management API endpoint and its credentials. Exactly one
// of Token (node API token) and Session (console login) is set.
type Profile struct {
	URL      string `json:"url"`
	Token    string `json:"token,omitempty"`
	Session  string `json:"session,omitempty"`
	User     string `json:"user,omitempty"`
	Role     string `json:"role,omitempty"`
	Expires  string `json:"session_expires,omitempty"`
	CAFile   string `json:"ca_file,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
}

func (p *Profile) authKind() string {
	switch {
	case p.Token != "":
		return "api-token"
	case p.Session != "":
		return "session"
	}
	return "none"
}

func (a *App) configPath() (string, error) {
	if a.ConfigPath != "" {
		return a.ConfigPath, nil
	}
	if p := a.Getenv("HCWCTL_CONFIG"); p != "" {
		return p, nil
	}
	dir := a.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot find the home directory: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "hcwctl", "config.json"), nil
}

func (a *App) loadConfig() (*Config, string, error) {
	path, err := a.configPath()
	if err != nil {
		return nil, "", err
	}
	cfg := &Config{Profiles: map[string]*Profile{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return cfg, path, nil
	}
	if err != nil {
		return nil, "", err
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(a.Stderr, "hcwctl: warning: %s is readable by other users (mode %v); run: chmod 600 %s\n", path, st.Mode().Perm(), path)
		}
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]*Profile{}
	}
	return cfg, path, nil
}

// saveConfig writes the file atomically with mode 0600 (directory 0700).
func saveConfig(path string, cfg *Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// profileName is the profile selected by --profile, $HCWCTL_PROFILE or the
// config's current profile.
func (a *App) profileName(cfg *Config) string {
	switch {
	case a.profile != "":
		return a.profile
	case a.Getenv("HCWCTL_PROFILE") != "":
		return a.Getenv("HCWCTL_PROFILE")
	case cfg != nil && cfg.Current != "":
		return cfg.Current
	}
	return "default"
}

// resolve returns the profile to use, with $HCWCTL_URL, $HCWCTL_CA and
// $HCWCTL_TOKEN applied on top.
func (a *App) resolve() (*Profile, string, error) {
	cfg, _, err := a.loadConfig()
	if err != nil {
		return nil, "", err
	}
	name := a.profileName(cfg)
	p := Profile{}
	if saved, ok := cfg.Profiles[name]; ok {
		p = *saved
	} else if a.profile != "" {
		return nil, name, fmt.Errorf("no profile %q (profiles: %s); run: hcwctl login --profile %s --url ...", name, profileList(cfg), name)
	}
	if u := a.Getenv("HCWCTL_URL"); u != "" {
		p.URL = u
	}
	if ca := a.Getenv("HCWCTL_CA"); ca != "" {
		p.CAFile, p.Insecure = ca, false
	}
	if t := a.Getenv("HCWCTL_TOKEN"); t != "" {
		p.Token, p.Session = t, ""
	}
	if p.URL == "" {
		return nil, name, fmt.Errorf("not logged in (profile %q); run: hcwctl login --url https://HOST:9443 ...", name)
	}
	if p.Token == "" && p.Session == "" {
		return nil, name, fmt.Errorf("profile %q has no credentials; run: hcwctl login", name)
	}
	return &p, name, nil
}

func profileList(cfg *Config) string {
	if len(cfg.Profiles) == 0 {
		return "none"
	}
	names := make([]string, 0, len(cfg.Profiles))
	for n := range cfg.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
