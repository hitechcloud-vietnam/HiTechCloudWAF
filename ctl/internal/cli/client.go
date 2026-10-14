package cli

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
	"time"
)

// Header names of the management API.
const (
	tokenHeader   = "X-HCW-API-TOKEN"
	sessionHeader = "X-HCW-Session"
)

// APIError is an error answer of the management API.
type APIError struct {
	Status int
	Code   string
	Msg    string
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("API error %d", e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	if e.Msg != "" {
		s += ": " + e.Msg
	}
	if e.Status == http.StatusUnauthorized && e.Code == "unauthorized" {
		s += " (run: hcwctl login)"
	}
	return s
}

type client struct {
	base    *url.URL
	hc      *http.Client
	header  string // auth header name
	cred    string // its value; never printed
	profile *Profile
}

// normalizeURL accepts "host:9443" or "https://host:9443/" and returns
// "https://host:9443". Plain HTTP is refused: credentials would travel in
// clear text and the management API only speaks HTTPS.
func normalizeURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("URL %q: only https:// is supported (the management API always uses TLS)", raw)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("URL %q has no host", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("URL %q: use only scheme, host, port and an optional path prefix", raw)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u, nil
}

// isLoopback reports whether host is localhost or a loopback address.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func errInsecure(host string) error {
	return usagef("--insecure is only allowed for loopback hosts (127.0.0.1, ::1, localhost), not %q; "+
		"pin the node certificate with --ca FILE instead (a self-signed node keeps it in data_dir/api.crt)", host)
}

// newClient builds an HTTP client for p. TLS certificates are verified
// against the system roots, or only against p.CAFile when set.
func newClient(p *Profile) (*client, error) {
	u, err := normalizeURL(p.URL)
	if err != nil {
		return nil, err
	}
	if p.Insecure && p.CAFile != "" {
		return nil, usagef("--ca and --insecure are mutually exclusive")
	}
	if p.Insecure && !isLoopback(u.Hostname()) {
		return nil, errInsecure(u.Hostname())
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if p.CAFile != "" {
		pem, err := os.ReadFile(p.CAFile)
		if err != nil {
			return nil, fmt.Errorf("CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %s contains no PEM certificate", p.CAFile)
		}
		tc.RootCAs = pool
	}
	if p.Insecure {
		tc.InsecureSkipVerify = true // loopback only, checked above
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tc
	c := &client{base: u, profile: p, hc: &http.Client{
		Transport: tr,
		Timeout:   2 * time.Minute,
		// Never forward credentials to another location.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	switch {
	case p.Token != "":
		c.header, c.cred = tokenHeader, p.Token
	case p.Session != "":
		c.header, c.cred = sessionHeader, p.Session
	}
	return c, nil
}

// client returns an API client for the selected profile.
func (a *App) client() (*client, error) {
	p, _, err := a.resolve()
	if err != nil {
		return nil, err
	}
	return newClient(p)
}

// do calls the API. body may be nil, json.RawMessage or any value; the
// envelope's data is decoded into out (nil: discarded).
func (c *client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var rd io.Reader
	if body != nil {
		var b []byte
		switch v := body.(type) {
		case json.RawMessage:
			b = v
		default:
			var err error
			if b, err = json.Marshal(v); err != nil {
				return err
			}
		}
		rd = bytes.NewReader(b)
	}
	u := *c.base
	u.Path += path
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "hcwctl/"+Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cred != "" {
		req.Header.Set(c.header, c.cred)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return explainTransport(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return fmt.Errorf("reading the response: %w", err)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
		Err  *string         `json:"err"`
		Msg  string          `json:"msg"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		snippet := strings.TrimSpace(string(raw))
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}
		return &APIError{Status: resp.StatusCode, Msg: "unexpected response (not the HiTechCloud WAF API?): " + clean(snippet)}
	}
	if env.Err != nil || resp.StatusCode/100 != 2 {
		e := &APIError{Status: resp.StatusCode, Msg: clean(env.Msg)}
		if env.Err != nil {
			e.Code = clean(*env.Err)
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
		return fmt.Errorf("decoding the response: %w", err)
	}
	return nil
}

func explainTransport(err error) error {
	var cve *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	switch {
	case errors.As(err, &hn):
		return fmt.Errorf("%w\nhint: the certificate does not match this host name; connect with a name it lists", err)
	case errors.As(err, &ua), errors.As(err, &cve):
		return fmt.Errorf("%w\nhint: the server certificate is not trusted; pin it with --ca FILE "+
			"(a self-signed node keeps it in data_dir/api.crt), or use --insecure for 127.0.0.1 only", err)
	}
	return err
}

// list is the API's collection shape.
type list[T any] struct {
	Data  []T `json:"data"`
	Total int `json:"total"`
}
