package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	goruntime "runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

// OWASP CRS inspection costs milliseconds of CPU per request and a Coraza
// transaction holds megabytes while it is open. The engine therefore
//   - runs at most Options.MaxInspections transactions at a time (other
//     requests wait for a slot, see acquireInspection),
//   - reads the request body before taking a slot, so a slow upload never
//     holds one, and
//   - closes every transaction as soon as the verdict is known, before the
//     request is proxied: a long response (SSE, long polling, downloads)
//     keeps nothing of the WAF alive.

// inspectWait is the longest a request waits for an inspection slot before
// it is answered 503: under sustained overload, shedding load is better
// than an ever-growing queue.
const inspectWait = 10 * time.Second

const defaultArgsBodyLimit = 128 << 10

func defaultMaxInspections() int { return 2 * goruntime.GOMAXPROCS(0) }

// acquireInspection takes an inspection slot. It gives up when the client
// goes away or after inspectWait.
func (e *Engine) acquireInspection(ctx context.Context) bool {
	select {
	case e.inspectSem <- struct{}{}:
		return true
	default:
	}
	t := time.NewTimer(inspectWait)
	defer t.Stop()
	select {
	case e.inspectSem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	case <-t.C:
		return false
	}
}

func (e *Engine) releaseInspection() { <-e.inspectSem }

// verdict is what a closed transaction leaves behind.
type verdict struct {
	it      *types.Interruption // the request is blocked
	monitor bool                // monitor mode: the rules would have blocked
	rules   []events.Rule
	tags    []string
}

// inspectSite runs the site's rule set on r and reports whether the request
// may proceed; when it may not, the answer has been written (blocked,
// refused or failed). release must be called once the request has been
// served, in both cases: it frees the spooled request body.
func (e *Engine) inspectSite(w http.ResponseWriter, r *http.Request, s *siteRT, ip net.IP) (pass bool, release func()) {
	var spool *bodySpool
	release = func() {
		if spool != nil {
			spool.release()
		}
	}
	fast := s.site.StaticFastPath && staticRequest(r)
	ct := r.Header.Get("Content-Type")
	// Bodies parsed into arguments (all but multipart and binary uploads)
	// cost CPU per byte inspected: ≈8 µs/byte at PL1, so 1 MiB ≈ 8 s.
	argsLimit, spoolLimit := int64(-1), int64(e.opt.BodyLimit)
	if hasBody(r) && !binaryContentType(ct) && !multipartContentType(ct) {
		argsLimit = int64(e.opt.ArgsBodyLimit)
		spoolLimit = argsLimit + 1 // enough to tell that it is too large
		if r.ContentLength > argsLimit && s.site.Mode == model.ModeBlock {
			e.tooLarge(w, r, s, ip)
			return false, release
		}
	}
	// Read the body before taking a slot, so a slow upload never holds one.
	// Bodies that rule 100001 leaves uninspected (binary uploads) stay put.
	if !fast && hasBody(r) && !binaryContentType(ct) {
		var err error
		if spool, err = spoolBody(r.Body, r.ContentLength, spoolLimit); err != nil {
			e.opt.Log.Debug("reading request body failed", "site", s.site.ID, "err", err)
			infoOf(r).set("error")
			http.Error(w, "bad request", http.StatusBadRequest)
			return false, release
		}
	}
	inspectLen := int64(-1) // all of the spool
	if spool != nil && argsLimit >= 0 && spool.n > argsLimit {
		if s.site.Mode == model.ModeBlock {
			e.tooLarge(w, r, s, ip)
			return false, release
		}
		// Monitor mode: inspect the first bytes only, and say so.
		inspectLen = argsLimit
		e.opt.Events.Add(e.event(r, s, ip, "body_limit", "monitor", 0))
	}
	if !e.acquireInspection(r.Context()) {
		busy(w, r)
		return false, release
	}
	held := true
	var body func() (io.Reader, error)
	if !fast && hasBody(r) {
		body = func() (io.Reader, error) {
			if spool == nil {
				// Custom rules re-enabled inspection of a binary body: read
				// it without holding the slot.
				e.releaseInspection()
				held = false
				var err error
				if spool, err = spoolBody(r.Body, r.ContentLength, int64(e.opt.BodyLimit)); err != nil {
					return nil, err
				}
				if !e.acquireInspection(r.Context()) {
					return nil, errBusy
				}
				held = true
			}
			if inspectLen >= 0 {
				return io.LimitReader(spool.reader(), inspectLen), nil
			}
			return spool.reader(), nil
		}
	}
	v, err := runTx(s, r, ip, body, fast)
	if held {
		e.releaseInspection()
	}
	if spool != nil {
		// Whatever the rules read, the upstream gets the whole body.
		r.Body = readCloser{Reader: ioMulti(spool.reader(), r.Body), c: r.Body}
	}
	switch {
	case errors.Is(err, errBusy):
		busy(w, r)
		return false, release
	case err != nil:
		e.opt.Log.Warn("waf inspection failed", "site", s.site.ID, "err", err)
		infoOf(r).set("error")
		http.Error(w, "bad request", http.StatusBadRequest)
		return false, release
	case v.it != nil:
		status := v.it.Status
		if status < 400 || status > 599 {
			status = http.StatusForbidden
		}
		ev := e.event(r, s, ip, "waf", "block", status)
		ev.Rules, ev.Tags = v.rules, v.tags
		e.block(w, r, ev)
		return false, release
	case v.monitor:
		ev := e.event(r, s, ip, "waf", "monitor", 0)
		ev.Rules, ev.Tags = v.rules, v.tags
		e.opt.Events.Add(ev)
	}
	return true, release
}

// runTx inspects r in a new transaction and closes it before returning:
// matched rules are collected first, nothing of the transaction is kept
// while the request is proxied.
func runTx(s *siteRT, r *http.Request, ip net.IP, body func() (io.Reader, error), headersOnly bool) (v verdict, err error) {
	tx := s.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()
	if headersOnly {
		earlyBlocking(tx)
	}
	it, err := inspect(tx, r, ip, body, headersOnly)
	if err != nil {
		return v, err
	}
	if it != nil {
		v.it = it
		v.rules, v.tags = matched(tx)
	} else if s.site.Mode == model.ModeMonitor && wouldBlock(tx) {
		v.monitor = true
		v.rules, v.tags = matched(tx)
	}
	return v, nil
}

// tooLarge refuses a body parsed into arguments that is larger than
// Options.ArgsBodyLimit.
func (e *Engine) tooLarge(w http.ResponseWriter, r *http.Request, s *siteRT, ip net.IP) {
	// Tell the client not to keep sending the rest of the body.
	w.Header().Set("Connection", "close")
	e.block(w, r, e.event(r, s, ip, "body_limit", "block", http.StatusRequestEntityTooLarge))
}

func busy(w http.ResponseWriter, r *http.Request) {
	infoOf(r).set("error")
	w.Header().Set("Retry-After", "5")
	http.Error(w, "503 Service Unavailable – server busy", http.StatusServiceUnavailable)
}

var errBusy = errors.New("no inspection slot")

// inspect runs Coraza phases 0–2 (only 0–1 when headersOnly). It mirrors
// coraza/http.processRequest but uses the resolved client address. body,
// when not nil, supplies the request body if the rules want to inspect it.
func inspect(tx types.Transaction, r *http.Request, ip net.IP, body func() (io.Reader, error), headersOnly bool) (*types.Interruption, error) {
	_, portStr, _ := net.SplitHostPort(r.RemoteAddr)
	port, _ := strconv.Atoi(portStr)
	tx.ProcessConnection(ip.String(), port, "", 0)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	if it := tx.ProcessRequestHeaders(); it != nil || headersOnly {
		return it, nil
	}
	if body != nil && tx.IsRequestBodyAccessible() {
		rd, err := body()
		if err != nil {
			return nil, err
		}
		it, _, err := tx.ReadRequestBodyFrom(rd)
		if err != nil {
			return nil, err
		}
		if it != nil {
			return it, nil
		}
	}
	return tx.ProcessRequestBody()
}

// earlyBlocking makes CRS evaluate the anomaly score at the end of phase 1
// (rule 949111) for this transaction only. Used by the static fast path,
// which skips phase 2 where the score is normally evaluated.
func earlyBlocking(tx types.Transaction) bool {
	v, ok := tx.(interface {
		Variables() plugintypes.TransactionVariables
	})
	if !ok {
		return false
	}
	v.Variables().TX().Set("early_blocking", []string{"1"})
	return true
}

// Rules whose match means "this request would be refused": the CRS anomaly
// evaluation (phase 2, and phase 1 with early blocking), the body parse
// errors of coraza.conf-recommended and the argument limit (wafpool.go).
var blockingRules = map[int]bool{949110: true, 949111: true, 200002: true, 200003: true, 100002: true, 100003: true}

// wouldBlock reports whether tx, run in DetectionOnly, would have blocked.
func wouldBlock(tx types.Transaction) bool {
	for _, m := range tx.MatchedRules() {
		if blockingRules[m.Rule().ID()] {
			return true
		}
	}
	return false
}

func hasBody(r *http.Request) bool {
	return r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
}

// binaryRe mirrors rule 100001 in wafpool.go: bodies of these types are not
// inspected.
var binaryRe = regexp.MustCompile(`(?i)^(?:application/(?:octet-stream|zip|gzip|x-tar|pdf|grpc)|image/|video/|audio/|font/)`)

func binaryContentType(ct string) bool { return ct != "" && binaryRe.MatchString(ct) }

// multipartContentType: files of multipart bodies are not parsed into
// arguments, so the arguments body limit does not apply to them.
func multipartContentType(ct string) bool {
	return len(ct) >= 10 && strings.EqualFold(ct[:10], "multipart/")
}

// Static fast path (site option static_fast_path).

var staticExts = map[string]bool{
	".css": true, ".js": true, ".mjs": true, ".map": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".webp": true, ".avif": true, ".ico": true, ".bmp": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
}

// Extensions of server-side scripts. "/index.php/app.css" runs index.php on
// many servers (PATH_INFO), so such a path is not a static file.
var scriptExts = map[string]bool{
	".php": true, ".php3": true, ".php4": true, ".php5": true, ".php7": true, ".phtml": true, ".phar": true,
	".asp": true, ".aspx": true, ".ashx": true, ".asmx": true, ".axd": true, ".jsp": true, ".jspx": true, ".do": true, ".action": true,
	".cgi": true, ".pl": true, ".py": true, ".rb": true, ".cfm": true, ".shtml": true,
}

// staticRequest reports whether r asks for a static file and carries no
// payload besides its headers: GET or HEAD, no query string, no body, a
// static extension, and no script name or ";" parameters in the path.
func staticRequest(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		return false
	}
	p := r.URL.Path
	if strings.ContainsAny(p, ";\\") {
		return false
	}
	if !staticExts[strings.ToLower(path.Ext(p))] {
		return false
	}
	dir := path.Dir(p)
	for dir != "/" && dir != "." {
		if scriptExts[strings.ToLower(path.Ext(dir))] {
			return false
		}
		dir = path.Dir(dir)
	}
	return true
}

// Request body spooling.

// spoolMem is the part of a body kept in memory; the rest goes to a
// temporary file (like Coraza's SecRequestBodyInMemoryLimit).
const spoolMem = 128 << 10

// bodySpool holds the first bytes of a request body (at most the
// inspection limit). The rest, if any, is still in the request.
type bodySpool struct {
	mem  []byte
	file *os.File
	n    int64
	once sync.Once
}

// spoolBody reads at most limit bytes of src. size is the announced
// Content-Length (-1 when unknown).
func spoolBody(src io.Reader, size, limit int64) (*bodySpool, error) {
	lr := io.LimitReader(src, limit)
	c := int64(16 << 10)
	if size >= 0 {
		c = min(size, limit, spoolMem) + 1 // +1: see EOF without growing
	}
	buf := make([]byte, 0, c)
	for {
		if len(buf) > spoolMem {
			return spill(buf, lr)
		}
		if len(buf) == cap(buf) {
			buf = slices.Grow(buf, min(len(buf), spoolMem+1-len(buf)))
		}
		n, err := lr.Read(buf[len(buf):min(cap(buf), spoolMem+1)])
		buf = buf[:len(buf)+n]
		if err == io.EOF {
			return &bodySpool{mem: buf, n: int64(len(buf))}, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func spill(head []byte, rest io.Reader) (*bodySpool, error) {
	f, err := os.CreateTemp("", "hcw-body-*")
	if err != nil {
		return nil, err
	}
	n, err := f.Write(head)
	if err == nil {
		var m int64
		m, err = io.Copy(f, rest)
		n += int(m)
	}
	if err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, err
	}
	return &bodySpool{file: f, n: int64(n)}, nil
}

// reader returns a new reader over the spooled bytes.
func (b *bodySpool) reader() io.Reader {
	if b.file != nil {
		return io.NewSectionReader(b.file, 0, b.n)
	}
	return bytes.NewReader(b.mem)
}

func (b *bodySpool) release() {
	b.once.Do(func() {
		if b.file != nil {
			_ = b.file.Close()
			_ = os.Remove(b.file.Name())
		}
	})
}
