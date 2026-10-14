// Package hcw is a client of the hcw-waf engine management API
// (docs/api/waf.openapi.yaml): requests authenticate with X-HCW-API-TOKEN
// and answers are wrapped as {"data": ..., "err": ..., "msg": ...}.
package hcw

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
	"sync"
	"time"
)

const (
	// TokenHeader carries the node API token.
	TokenHeader = "X-HCW-API-TOKEN"

	// maxResponseSize bounds one answer: 1000 events of a busy node fit
	// comfortably.
	maxResponseSize = 16 << 20
	// maxRequestSize bounds one site object sent back to the node.
	maxRequestSize = 4 << 20

	defaultTimeout = 30 * time.Second
	userAgent      = "HiTechCloud-WAF-MCP/2"
)

// APIError is an error answer of the management API. Code and Msg are
// sanitized: they may quote input and are shown to the model.
type APIError struct {
	Status int
	Code   string
	Msg    string
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("management API error (HTTP %d", e.Status)
	if e.Code != "" {
		s += ", " + e.Code
	}
	s += ")"
	if e.Msg != "" {
		s += ": " + e.Msg
	}
	return s
}

// ClientConfig configures one instance client.
type ClientConfig struct {
	BaseURL string
	// Token is the node API token. It is only ever placed in the
	// X-HCW-API-TOKEN request header.
	Token   string
	CAFile  string
	Timeout time.Duration
}

// Client talks to one hcw-waf node.
type Client struct {
	base  *url.URL
	hc    *http.Client
	token string

	// writeMu serialises read-modify-write updates of sites made through
	// this server, so two tool calls cannot overwrite each other.
	writeMu sync.Mutex
}

// IsLoopbackHost reports whether host (without port) is localhost or a
// loopback address.
func IsLoopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ParseBaseURL validates the address of a node: an absolute https URL, or
// http only for a loopback host, without credentials, query or fragment.
func ParseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, errors.New("base_url is not a valid URL")
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("base_url must be an absolute https:// URL")
	}
	if u.Scheme == "http" && !IsLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("base_url %s: plain HTTP is only allowed to a loopback host; use https:// (and ca_file for a self-signed node certificate)", u.Redacted())
	}
	if u.User != nil {
		return nil, errors.New("base_url must not contain credentials; use token_file or token_env")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("base_url must not contain a query or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// LoadCAFile returns a pool holding the PEM certificates of path.
func LoadCAFile(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca_file %s contains no PEM certificate", path)
	}
	return pool, nil
}

// NewClient builds a client. TLS certificates are always verified: against
// the system roots, or only against CAFile when it is set.
func NewClient(cfg ClientConfig) (*Client, error) {
	base, err := ParseBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.Token == "" {
		return nil, errors.New("API token is empty")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pool, err := LoadCAFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tc.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tc
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		base:  base,
		token: cfg.Token,
		hc: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			// The token travels in a custom header that net/http does not
			// strip on a cross-origin redirect, so no redirect is followed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Do calls the API. body (nil or a JSON-marshalable value) is sent as JSON;
// the envelope's data is decoded into out (nil: discarded).
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		if len(b) > maxRequestSize {
			return errors.New("request body exceeds 4 MiB")
		}
		reader = bytes.NewReader(b)
	}
	u := *c.base
	u.Path = c.base.Path + path
	u.RawQuery = ""
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(TokenHeader, c.token)

	resp, err := c.hc.Do(req)
	if err != nil {
		return transportError(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(raw) > maxResponseSize {
		return errors.New("response exceeds 16 MiB")
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return &APIError{Status: resp.StatusCode, Msg: "redirect refused (the token is never sent to another location); check base_url"}
	}
	var env struct {
		Data json.RawMessage `json:"data"`
		Err  *string         `json:"err"`
		Msg  string          `json:"msg"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return &APIError{Status: resp.StatusCode, Msg: "unexpected response (is base_url an hcw-waf management API?)"}
	}
	if env.Err != nil || resp.StatusCode/100 != 2 {
		e := &APIError{Status: resp.StatusCode, Msg: Clean(env.Msg, 300)}
		if env.Err != nil {
			e.Code = Clean(*env.Err, 40)
		}
		return e
	}
	if out == nil {
		return nil
	}
	if p, ok := out.(*json.RawMessage); ok {
		*p = env.Data
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// transportError explains TLS failures; it never quotes request headers.
func transportError(err error) error {
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var cve *tls.CertificateVerificationError
	switch {
	case errors.As(err, &hn):
		return fmt.Errorf("TLS: the node certificate does not match the host name of base_url: %w", err)
	case errors.As(err, &ua), errors.As(err, &cve):
		return fmt.Errorf("TLS: the node certificate is not trusted; set ca_file to the node certificate (data_dir/api.crt) or its CA: %w", err)
	}
	return fmt.Errorf("request failed: %w", err)
}
