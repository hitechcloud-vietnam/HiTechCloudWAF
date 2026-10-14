// Package engine talks to the management API of a WAF engine instance and
// replicates configuration between instances.
package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
)

const maxBody = 16 << 20

// Client is an authenticated client for one engine instance.
type Client struct {
	base   *url.URL
	cfg    config.Engine
	http   *http.Client
	header http.Header
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// New builds a client. The API token is never sent over plain HTTP to a
// non-loopback host, and TLS verification can only be relaxed for loopback.
func New(cfg config.Engine) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("engine base_url %q must be an absolute http(s) URL", cfg.BaseURL)
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return nil, errors.New("engine token must not be sent over plain HTTP to a non-loopback host")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s has no PEM certificate", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.InsecureSkipVerify {
		if !isLoopback(u.Hostname()) {
			return nil, errors.New("insecure_skip_verify is only allowed for loopback engine URLs; use ca_file")
		}
		tlsCfg.InsecureSkipVerify = true
	}
	c := &Client{
		base: u,
		cfg:  cfg,
		http: &http.Client{
			Timeout:   cfg.Timeout.Duration,
			Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: nil},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// The token header would follow redirects to any host.
				return http.ErrUseLastResponse
			},
		},
		header: http.Header{},
	}
	c.header.Set("Accept", "application/json")
	c.header.Set("Content-Type", "application/json")
	c.header.Set("User-Agent", "hitechcloud-waf-cluster/1")
	if cfg.Token != "" {
		c.header.Set(cfg.TokenHeader, cfg.Token)
	}
	return c, nil
}

// Do sends a request and returns the decoded JSON body. A non-null "err"
// field of the engine's response envelope is reported as an error.
func (c *Client) Do(ctx context.Context, method, path, query string, body any) (any, error) {
	u := *c.base
	u.Path = c.base.Path + path
	u.RawQuery = query
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	req.Header = c.header.Clone()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBody {
		return nil, fmt.Errorf("%s %s: response too large", method, path)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, truncate(raw))
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%s %s: invalid JSON: %w", method, path, err)
	}
	if m, ok := v.(map[string]any); ok {
		if e, ok := m["err"]; ok && e != nil && e != "" {
			return nil, fmt.Errorf("%s %s: engine error %v: %v", method, path, e, m["msg"])
		}
	}
	return v, nil
}

// Health reports whether the engine answers its health endpoint.
func (c *Client) Health(ctx context.Context) error {
	_, err := c.Do(ctx, http.MethodGet, c.cfg.HealthPath, "", nil)
	return err
}

// List returns the items of a resource collection.
func (c *Client) List(ctx context.Context, r config.Resource) ([]map[string]any, error) {
	v, err := c.Do(ctx, http.MethodGet, r.Path, r.ListQuery, nil)
	if err != nil {
		return nil, err
	}
	node := v
	if r.ItemsPath != "." {
		for _, part := range strings.Split(r.ItemsPath, ".") {
			m, ok := node.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("list %s: %q is not an object", r.Name, part)
			}
			node = m[part]
		}
	}
	if node == nil {
		return nil, nil
	}
	arr, ok := node.([]any)
	if !ok {
		return nil, fmt.Errorf("list %s: items_path %q is not an array", r.Name, r.ItemsPath)
	}
	out := make([]map[string]any, 0, len(arr))
	for _, it := range arr {
		m, ok := it.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("list %s: item is not an object", r.Name)
		}
		out = append(out, m)
	}
	return out, nil
}

func truncate(b []byte) string {
	const n = 512
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}
