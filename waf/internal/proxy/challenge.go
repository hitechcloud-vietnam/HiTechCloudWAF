package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"math/bits"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

// Reserved path prefix for engine endpoints on every site.
const hcwPrefix = "/.hcw/"

const (
	cookieBot  = "hcw_bot"
	cookieAuth = "hcw_auth"
	// A challenge must be solved within this time.
	challengeMaxAge = 5 * time.Minute
)

// ipKey groups addresses so a client keeps its pass: IPv4 as is, IPv6 by /64
// (privacy addresses rotate inside the prefix).
func ipKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

func (e *Engine) mac(parts ...string) string {
	h := hmac.New(sha256.New, e.opt.Secret)
	h.Write([]byte(strings.Join(parts, "|")))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// passToken is "<exp>.<mac>" bound to site, kind, client and a version
// (for auth, a digest of the password hash so changing it logs everyone out).
func (e *Engine) passToken(s *siteRT, kind, version string, ip net.IP, ttl time.Duration) string {
	exp := strconv.FormatInt(time.Now().Add(ttl).Unix(), 10)
	return exp + "." + e.mac("pass", kind, strconv.Itoa(s.site.ID), version, ipKey(ip), exp)
}

func (e *Engine) validPass(r *http.Request, name string, s *siteRT, kind, version string, ip net.IP) bool {
	c, err := r.Cookie(name)
	if err != nil {
		return false
	}
	exp, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	n, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || time.Now().Unix() > n {
		return false
	}
	want := e.mac("pass", kind, strconv.Itoa(s.site.ID), version, ipKey(ip), exp)
	return hmac.Equal([]byte(sig), []byte(want))
}

func setPass(w http.ResponseWriter, name, value string, ttl time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

func excluded(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// safeReturn keeps redirects on the same site.
func safeReturn(r string) string {
	if !strings.HasPrefix(r, "/") || strings.HasPrefix(r, "//") || strings.HasPrefix(r, "/\\") || strings.ContainsAny(r, "\r\n") {
		return "/"
	}
	return r
}

func authVersion(hash string) string {
	sum := sha256.Sum256([]byte(hash))
	return hex.EncodeToString(sum[:6])
}

// ---- bot challenge ----

// newChallenge returns "<ts>.<rand>.<mac>" bound to site and client.
func (e *Engine) newChallenge(s *siteRT, ip net.IP) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	rnd := base64.RawURLEncoding.EncodeToString(b)
	return ts + "." + rnd + "." + e.mac("chal", strconv.Itoa(s.site.ID), strconv.Itoa(s.site.Bot.Difficulty), ipKey(ip), ts, rnd)
}

func (e *Engine) checkChallenge(s *siteRT, ip net.IP, nonce, counter string) bool {
	parts := strings.Split(nonce, ".")
	if len(parts) != 3 || len(counter) == 0 || len(counter) > 20 {
		return false
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Since(time.Unix(ts, 0)) > challengeMaxAge || time.Until(time.Unix(ts, 0)) > time.Minute {
		return false
	}
	want := e.mac("chal", strconv.Itoa(s.site.ID), strconv.Itoa(s.site.Bot.Difficulty), ipKey(ip), parts[0], parts[1])
	if !hmac.Equal([]byte(parts[2]), []byte(want)) {
		return false
	}
	if _, err := strconv.ParseUint(counter, 10, 64); err != nil {
		return false
	}
	return leadingZeroBits(sha256.Sum256([]byte(nonce+":"+counter))) >= s.site.Bot.Difficulty
}

func leadingZeroBits(h [32]byte) int {
	n := 0
	for _, b := range h {
		if b == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(b)
	}
	return n
}

// handleEngineEndpoint serves /.hcw/*. It reports whether it handled r.
func (e *Engine) handleEngineEndpoint(w http.ResponseWriter, r *http.Request, s *siteRT, ip net.IP, isTLS bool) bool {
	if !strings.HasPrefix(r.URL.Path, hcwPrefix) {
		return false
	}
	switch r.URL.Path {
	case hcwPrefix + "verify":
		if r.Method != http.MethodPost || !(s.site.Bot.Enabled || s.site.ThreatIntel == model.ThreatIntelChallenge) {
			http.NotFound(w, r)
			return true
		}
		_ = r.ParseForm()
		if !e.checkChallenge(s, ip, r.PostForm.Get("nonce"), r.PostForm.Get("counter")) {
			ev := e.event(r, s, ip, "bot", "block", http.StatusForbidden)
			e.opt.Events.Add(ev)
			http.Error(w, "challenge failed", http.StatusForbidden)
			return true
		}
		ttl := time.Duration(s.site.Bot.TTLSec) * time.Second
		setPass(w, cookieBot, e.passToken(s, "bot", strconv.Itoa(s.site.Bot.Difficulty), ip, ttl), ttl, isTLS)
		http.Redirect(w, r, safeReturn(r.PostForm.Get("return")), http.StatusSeeOther)
	case hcwPrefix + "auth":
		if r.Method != http.MethodPost || !s.site.Auth.Enabled {
			http.NotFound(w, r)
			return true
		}
		_ = r.ParseForm()
		ret := safeReturn(r.PostForm.Get("return"))
		key := "auth|" + strconv.Itoa(s.site.ID) + "|" + ipKey(ip)
		// 10 attempts per 10 minutes, then a 15 minute lock.
		if !e.limiter.allow(key, 10, 10*time.Minute, 15*time.Minute, time.Now()) {
			e.block(w, r, e.event(r, s, ip, "auth", "block", http.StatusTooManyRequests))
			return true
		}
		if bcrypt.CompareHashAndPassword([]byte(s.site.Auth.PasswordHash), []byte(r.PostForm.Get("password"))) != nil {
			e.opt.Events.Add(e.event(r, s, ip, "auth", "block", http.StatusUnauthorized))
			e.writeAuthPage(w, r, s, ret, true)
			return true
		}
		ttl := time.Duration(s.site.Auth.TTLSec) * time.Second
		setPass(w, cookieAuth, e.passToken(s, "auth", authVersion(s.site.Auth.PasswordHash), ip, ttl), ttl, isTLS)
		http.Redirect(w, r, ret, http.StatusSeeOther)
	case hcwPrefix + "logout":
		http.SetCookie(w, &http.Cookie{Name: cookieAuth, Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
	return true
}

// challenges enforces auth then bot checks. tiFeed, when set, names the
// threat-intelligence feed listing the client of a site in challenge mode:
// the bot challenge then applies even if it is not enabled for everybody.
// It reports whether the request may continue.
func (e *Engine) challenges(w http.ResponseWriter, r *http.Request, s *siteRT, ip net.IP, tiFeed string) bool {
	if a := s.site.Auth; a.Enabled && !excluded(r.URL.Path, a.ExcludePaths) {
		if !e.validPass(r, cookieAuth, s, "auth", authVersion(a.PasswordHash), ip) {
			e.writeAuthPage(w, r, s, r.URL.RequestURI(), false)
			return false
		}
	}
	if b := s.site.Bot; (b.Enabled || tiFeed != "") && !excluded(r.URL.Path, b.ExcludePaths) {
		if !e.validPass(r, cookieBot, s, "bot", strconv.Itoa(b.Difficulty), ip) {
			// Verified crawlers cannot run the JavaScript; WAF rules still apply.
			if e.verifiedBot(r, s, ip) {
				return true
			}
			if tiFeed != "" {
				ev := e.event(r, s, ip, "threat_intel", "challenge", http.StatusForbidden)
				ev.Feed = tiFeed
				e.opt.Events.Add(ev)
			}
			e.writeBotPage(w, r, s, ip)
			return false
		}
	}
	return true
}

var pageCSS = template.CSS(`:root{--bg:#f8fafc;--card:#fff;--text:#0f172a;--muted:#64748b}
@media (prefers-color-scheme:dark){:root{--bg:#0b1220;--card:#111a2e;--text:#e2e8f0;--muted:#94a3b8}}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);font-family:Inter,"Segoe UI",system-ui,sans-serif}
.c{max-width:440px;width:100%;margin:16px;padding:32px;background:var(--card);border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.08);text-align:center;box-sizing:border-box}
h1{font-size:20px;margin:0 0 8px}p{color:var(--muted);line-height:1.5;margin:6px 0}
.bar{height:6px;border-radius:3px;background:rgba(127,127,127,.2);overflow:hidden;margin:18px 0}
.bar i{display:block;height:100%;width:30%;background:var(--brand);animation:m 1.2s infinite ease-in-out}
@keyframes m{0%{margin-left:-30%}100%{margin-left:100%}}
input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid rgba(127,127,127,.4);border-radius:8px;font:inherit;background:transparent;color:inherit;margin:12px 0}
button{width:100%;padding:10px;border:0;border-radius:8px;background:var(--brand);color:#fff;font:inherit;cursor:pointer}
.err{color:#dc2626}small{display:block;margin-top:18px;color:var(--muted);font-size:12px}`)

var botTmpl = template.Must(template.New("bot").Parse(`<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Đang kiểm tra trình duyệt – {{.Brand.Name}}</title>
<style>:root{--brand:{{.Brand.Color}}}{{.CSS}}</style></head><body><div class="c">
<h1>Đang kiểm tra trình duyệt của bạn…</h1>
<p>Checking your browser before accessing the site.</p>
<div class="bar"><i></i></div>
<noscript><p class="err">Vui lòng bật JavaScript để tiếp tục. / Please enable JavaScript.</p></noscript>
<form id="f" method="post" action="/.hcw/verify">
<input type="hidden" name="nonce" value="{{.Nonce}}"><input type="hidden" name="counter" id="n">
<input type="hidden" name="return" value="{{.Return}}"></form>
<small>Protected by {{.Brand.Name}}</small></div>
<script>
(function(){
var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function sha(s){var m=[],l=s.length*8,i,j;for(i=0;i<s.length;i++)m[i>>2]|=(s.charCodeAt(i)&255)<<(24-(i%4)*8);m[l>>5]|=0x80<<(24-l%32);m[((l+64>>9)<<4)+15]=l;
var h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],w=new Array(64);
for(i=0;i<m.length;i+=16){var a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],k=h[7];
for(j=0;j<64;j++){if(j<16)w[j]=m[i+j]|0;else{var x=w[j-15],y=w[j-2];w[j]=(((x>>>7|x<<25)^(x>>>18|x<<14)^(x>>>3))+w[j-7]+((y>>>17|y<<15)^(y>>>19|y<<13)^(y>>>10))+w[j-16])|0;}
var t1=(k+((e>>>6|e<<26)^(e>>>11|e<<21)^(e>>>25|e<<7))+((e&f)^(~e&g))+K[j]+w[j])|0,t2=(((a>>>2|a<<30)^(a>>>13|a<<19)^(a>>>22|a<<10))+((a&b)^(a&c)^(b&c)))|0;
k=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;}
h[0]=(h[0]+a)|0;h[1]=(h[1]+b)|0;h[2]=(h[2]+c)|0;h[3]=(h[3]+d)|0;h[4]=(h[4]+e)|0;h[5]=(h[5]+f)|0;h[6]=(h[6]+g)|0;h[7]=(h[7]+k)|0;}return h[0];}
function clz(v){return v===0?32:Math.clz32(v);}
var nonce={{.Nonce}},bits={{.Difficulty}},c=0;
function step(){for(var i=0;i<20000;i++,c++){if(clz(sha(nonce+":"+c))>=bits){document.getElementById("n").value=c;document.getElementById("f").submit();return;}}setTimeout(step,0);}
setTimeout(step,10);
})();
</script></body></html>`))

var authTmpl = template.Must(template.New("auth").Parse(`<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Yêu cầu xác thực – {{.Brand.Name}}</title>
<style>:root{--brand:{{.Brand.Color}}}{{.CSS}}</style></head><body><div class="c">
<h1>Trang được bảo vệ</h1>
<p>Nhập mật khẩu để truy cập. / Enter the password to continue.</p>
{{if .Failed}}<p class="err">Mật khẩu không đúng. / Wrong password.</p>{{end}}
<form method="post" action="/.hcw/auth">
<input type="password" name="password" autocomplete="current-password" autofocus required>
<input type="hidden" name="return" value="{{.Return}}">
<button type="submit">Tiếp tục</button></form>
<small>Protected by {{.Brand.Name}}</small></div></body></html>`))

type challengePage struct {
	Brand      Brand
	CSS        template.CSS
	Nonce      string
	Difficulty int
	Return     string
	Failed     bool
}

func pageHeaders(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
}

func (e *Engine) writeBotPage(w http.ResponseWriter, r *http.Request, s *siteRT, ip net.IP) {
	infoOf(r).set("challenged")
	pageHeaders(w, http.StatusForbidden)
	if err := botTmpl.Execute(w, challengePage{Brand: e.opt.Brand, CSS: pageCSS, Nonce: e.newChallenge(s, ip), Difficulty: s.site.Bot.Difficulty, Return: safeReturn(r.URL.RequestURI())}); err != nil {
		e.opt.Log.Error("render bot page", "err", fmt.Sprint(err))
	}
}

func (e *Engine) writeAuthPage(w http.ResponseWriter, r *http.Request, s *siteRT, ret string, failed bool) {
	infoOf(r).set("challenged")
	pageHeaders(w, http.StatusUnauthorized)
	if err := authTmpl.Execute(w, challengePage{Brand: e.opt.Brand, CSS: pageCSS, Return: safeReturn(ret), Failed: failed}); err != nil {
		e.opt.Log.Error("render auth page", "err", fmt.Sprint(err))
	}
}
