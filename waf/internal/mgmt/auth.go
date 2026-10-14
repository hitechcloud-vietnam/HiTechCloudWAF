package mgmt

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/audit"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/users"
)

// SessionHeader carries a console session token.
const SessionHeader = "X-HCW-Session"

// principal is the authenticated caller.
type principal struct {
	name    string
	role    string
	account bool // a console user (false: the node API token)
}

func (p principal) admin() bool { return p.role == users.RoleAdmin }

// loginGuard limits failed logins per client address and per username (a
// higher limit, so distributed guessing is slowed without letting one
// attacker lock an account out too easily).
type loginGuard struct {
	mu   sync.Mutex
	fail map[string][]time.Time
}

const (
	maxLoginFailures     = 10
	maxUserLoginFailures = 50
	loginWindow          = 15 * time.Minute
	maxGuardEntries      = 50000
)

func (g *loginGuard) recentLocked(key string, now time.Time) int {
	recent := g.fail[key][:0]
	for _, t := range g.fail[key] {
		if now.Sub(t) < loginWindow {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(g.fail, key) // keep the map from growing with old addresses
	} else {
		g.fail[key] = recent
	}
	return len(recent)
}

func (g *loginGuard) blocked(ip, username string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fail == nil {
		g.fail = map[string][]time.Time{}
	}
	return g.recentLocked(ip, now) >= maxLoginFailures || g.recentLocked("user\x00"+username, now) >= maxUserLoginFailures
}

func (g *loginGuard) failed(ip, username string, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fail == nil {
		g.fail = map[string][]time.Time{}
	}
	if len(g.fail) >= maxGuardEntries {
		for k := range g.fail {
			g.recentLocked(k, now)
		}
	}
	if len(g.fail) >= maxGuardEntries {
		return // flooded with fresh addresses: per-user limit still applies
	}
	g.fail[ip] = append(g.fail[ip], now)
	if k := "user\x00" + username; len(g.fail[k]) < maxUserLoginFailures*2 {
		g.fail[k] = append(g.fail[k], now)
	}
}

// loginSlots bounds concurrent password checks (bcrypt is CPU heavy).
var loginSlots = make(chan struct{}, 8)

func clientHost(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// authenticate resolves the caller from the API token or a session.
func (a *API) authenticate(r *http.Request) (principal, bool) {
	if a.authorized(r) {
		return principal{name: "api-token", role: users.RoleAdmin}, true
	}
	if a.Users != nil {
		if s, ok := a.Users.Session(r.Header.Get(SessionHeader)); ok {
			return principal{name: s.Username, role: s.Role, account: true}, true
		}
	}
	return principal{}, false
}

// viewerAllowed lists what read-only users may call besides GET requests.
func viewerAllowed(r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}
	return r.URL.Path == "/api/auth/logout" || strings.HasPrefix(r.URL.Path, "/api/open/me/")
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if a.Users == nil {
		fail(w, http.StatusNotFound, "not_found", errors.New("user accounts are not enabled"))
		return
	}
	ip := clientHost(r)
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		OTP      string `json:"otp"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, http.StatusBadRequest, "invalid", err)
		return
	}
	if a.guard.blocked(ip, in.Username, time.Now()) {
		fail(w, http.StatusTooManyRequests, "locked", errors.New("too many failed logins, try again in 15 minutes"))
		return
	}
	select {
	case loginSlots <- struct{}{}:
		defer func() { <-loginSlots }()
	case <-time.After(5 * time.Second):
		fail(w, http.StatusTooManyRequests, "busy", errors.New("too many logins in progress, try again"))
		return
	case <-r.Context().Done():
		return
	}
	tok, sess, err := a.Users.Login(in.Username, in.Password, in.OTP)
	switch {
	case errors.Is(err, users.ErrOTPRequired):
		// Correct password: ask for the second factor without counting a failure.
		fail(w, http.StatusUnauthorized, "otp_required", err)
		return
	case err != nil:
		a.guard.failed(ip, in.Username, time.Now())
		if a.Audit != nil {
			a.Audit.Add(audit.Entry{Time: time.Now().UTC(), User: in.Username, IP: ip, Action: "login", Status: http.StatusUnauthorized})
		}
		a.Log.Warn("console login failed", "user", in.Username, "ip", ip, "err", err)
		fail(w, http.StatusUnauthorized, "unauthorized", err)
		return
	}
	a.Log.Info("console login", "user", sess.Username, "role", sess.Role, "ip", ip)
	if a.Audit != nil {
		a.Audit.Add(audit.Entry{Time: time.Now().UTC(), User: sess.Username, IP: ip, Action: "login", Status: http.StatusOK})
	}
	ok(w, map[string]any{"token": tok, "username": sess.Username, "role": sess.Role, "expires": sess.Expires})
}

func (a *API) registerAccountRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/auth/login", a.login)
	mux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if a.Users != nil {
			a.Users.Logout(r.Header.Get(SessionHeader))
		}
		ok(w, nil)
	})
	mux.HandleFunc("GET /api/open/me", func(w http.ResponseWriter, r *http.Request) {
		p := callerOf(r)
		out := map[string]any{"username": p.name, "role": p.role, "account": p.account, "accounts_enabled": a.Users != nil}
		if p.account {
			for _, u := range a.Users.List() {
				if u.Username == p.name {
					out["totp"] = u.TOTP
				}
			}
		}
		ok(w, out)
	})
	me := func(f func(w http.ResponseWriter, r *http.Request, p principal)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			p := callerOf(r)
			if !p.account {
				fail(w, http.StatusBadRequest, "no_account", errors.New("the API token has no account; log in as a user"))
				return
			}
			f(w, r, p)
		}
	}
	mux.HandleFunc("POST /api/open/me/password", me(func(w http.ResponseWriter, r *http.Request, p principal) {
		var in struct{ Current, New string }
		if err := decode(r, &in); err != nil {
			fail(w, http.StatusBadRequest, "invalid", err)
			return
		}
		if err := a.Users.ChangePassword(p.name, in.Current, in.New, r.Header.Get(SessionHeader)); err != nil {
			fail(w, http.StatusBadRequest, "invalid", err)
			return
		}
		ok(w, nil)
	}))
	mux.HandleFunc("POST /api/open/me/totp/setup", me(func(w http.ResponseWriter, _ *http.Request, p principal) {
		secret, err := a.Users.BeginTOTP(p.name)
		if err != nil {
			fail(w, http.StatusBadRequest, "invalid", err)
			return
		}
		issuer := "HiTechCloud WAF"
		if b, ok := a.Brand.(interface{ BrandName() string }); ok && b.BrandName() != "" {
			issuer = b.BrandName()
		}
		u := users.OTPAuthURL(issuer, p.name, secret)
		png, err := qrcode.Encode(u, qrcode.Medium, 256)
		if err != nil {
			fail(w, http.StatusInternalServerError, "qr", err)
			return
		}
		ok(w, map[string]string{"secret": secret, "url": u, "qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)})
	}))
	mux.HandleFunc("POST /api/open/me/totp/enable", me(func(w http.ResponseWriter, r *http.Request, p principal) {
		var in struct{ Code string }
		if err := decode(r, &in); err != nil {
			fail(w, http.StatusBadRequest, "invalid", err)
			return
		}
		if err := a.Users.ConfirmTOTP(p.name, in.Code); err != nil {
			fail(w, http.StatusBadRequest, "invalid", err)
			return
		}
		ok(w, nil)
	}))
	mux.HandleFunc("POST /api/open/me/totp/disable", me(func(w http.ResponseWriter, r *http.Request, p principal) {
		var in struct{ Code string }
		if err := decode(r, &in); err != nil {
			fail(w, http.StatusBadRequest, "invalid", err)
			return
		}
		if err := a.Users.DisableTOTP(p.name, in.Code); err != nil {
			fail(w, http.StatusBadRequest, "invalid", err)
			return
		}
		ok(w, nil)
	}))

	// User management (admins).
	mux.HandleFunc("GET /api/open/users", func(w http.ResponseWriter, r *http.Request) {
		if !adminOnly(w, r) {
			return
		}
		if a.Users == nil {
			ok(w, list[users.PublicUser]{Data: []users.PublicUser{}})
			return
		}
		l := a.Users.List()
		ok(w, list[users.PublicUser]{Data: l, Total: len(l)})
	})
	accounts := func(f func(*http.Request) error) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if a.Users == nil {
				fail(w, http.StatusNotFound, "not_found", errors.New("user accounts are not enabled"))
				return
			}
			if err := f(r); err != nil {
				code := http.StatusBadRequest
				if errors.Is(err, users.ErrNotFound) {
					code = http.StatusNotFound
				}
				fail(w, code, "invalid", err)
				return
			}
			a.Log.Info("users changed", "by", callerOf(r).name, "method", r.Method)
			ok(w, nil)
		}
	}
	mux.HandleFunc("POST /api/open/users", accounts(func(r *http.Request) error {
		var in struct{ Username, Password, Role string }
		if err := decode(r, &in); err != nil {
			return err
		}
		return a.Users.Create(in.Username, in.Password, in.Role)
	}))
	mux.HandleFunc("PUT /api/open/users", accounts(func(r *http.Request) error {
		var in struct {
			Username, Password, Role string
			ResetTOTP                bool `json:"reset_totp"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		return a.Users.Update(in.Username, in.Password, in.Role, in.ResetTOTP)
	}))
	mux.HandleFunc("DELETE /api/open/users", accounts(func(r *http.Request) error {
		var in struct{ Usernames []string }
		if err := decode(r, &in); err != nil {
			return err
		}
		for _, u := range in.Usernames {
			if u == callerOf(r).name {
				return errors.New("you cannot delete your own account")
			}
			if err := a.Users.Delete(u); err != nil {
				return err
			}
		}
		return nil
	}))
}

type ctxPrincipal struct{}

func callerOf(r *http.Request) principal {
	p, _ := r.Context().Value(ctxPrincipal{}).(principal)
	return p
}

func withCaller(r *http.Request, p principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxPrincipal{}, p))
}
