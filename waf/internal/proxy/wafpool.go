package proxy

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

// wafKey identifies a Coraza configuration. Sites with the same settings
// share one compiled rule set, which keeps memory flat with many sites.
type wafKey struct {
	mode      string
	paranoia  int
	threshold int
	disabled  string
	bodyLimit int
	custom    string
}

func keyFor(s *model.Site, bodyLimit int) wafKey {
	d := append([]int(nil), s.DisabledRules...)
	sort.Ints(d)
	return wafKey{mode: s.Mode, paranoia: s.Paranoia, threshold: s.AnomalyThreshold, disabled: fmt.Sprint(d), bodyLimit: bodyLimit, custom: s.CustomRules}
}

const allowedContentTypes = "|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json| |application/octet-stream| |application/grpc| |application/grpc-web|"

// WAFPool compiles and caches Coraza instances.
type WAFPool struct {
	mu    sync.Mutex
	cache map[wafKey]coraza.WAF
	extra string
}

// NewWAFPool creates a pool. extraDirectives are appended after the CRS
// (custom rules of the operator).
func NewWAFPool(extraDirectives string) *WAFPool {
	return &WAFPool{cache: map[wafKey]coraza.WAF{}, extra: extraDirectives}
}

// Directives returns the SecLang configuration for k.
func (p *WAFPool) directives(k wafKey, disabled []int) string {
	engine := "On"
	if k.mode == model.ModeMonitor {
		engine = "DetectionOnly"
	}
	var b strings.Builder
	b.WriteString("Include @coraza.conf-recommended\n")
	fmt.Fprintf(&b, "SecRuleEngine %s\n", engine)
	b.WriteString("SecRequestBodyAccess On\nSecResponseBodyAccess Off\n")
	fmt.Fprintf(&b, "SecRequestBodyLimit %d\nSecRequestBodyInMemoryLimit %d\n", k.bodyLimit, min(k.bodyLimit, 131072))
	// Keep serving large uploads; only the first bodyLimit bytes are inspected.
	b.WriteString("SecRequestBodyLimitAction ProcessPartial\n")
	// Binary uploads are not parsed by any body processor; scanning them
	// with text rules costs seconds per megabyte and finds nothing.
	b.WriteString(`SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^(?:application/(?:octet-stream|zip|gzip|x-tar|pdf|grpc)|image/|video/|audio/|font/)" "id:100001,phase:1,pass,nolog,ctl:requestBodyAccess=Off"` + "\n")
	b.WriteString("Include @crs-setup.conf.example\n")
	fmt.Fprintf(&b, `SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"`+"\n", k.paranoia)
	fmt.Fprintf(&b, `SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=4"`+"\n", k.threshold)
	// CRS default content types plus binary uploads (inspected as metadata only).
	fmt.Fprintf(&b, `SecAction "id:900220,phase:1,pass,t:none,nolog,setvar:'tx.allowed_request_content_type=%s'"`+"\n", allowedContentTypes)
	b.WriteString("Include @owasp_crs/*.conf\n")
	for _, id := range disabled {
		fmt.Fprintf(&b, "SecRuleRemoveById %d\n", id)
	}
	if p.extra != "" {
		b.WriteString(p.extra + "\n")
	}
	if k.custom != "" {
		b.WriteString(k.custom + "\n")
	}
	return b.String()
}

// Get returns the WAF for site s, compiling it on first use.
func (p *WAFPool) Get(s *model.Site, bodyLimit int) (coraza.WAF, error) {
	if s.Mode == model.ModeOff {
		return nil, nil
	}
	k := keyFor(s, bodyLimit)
	p.mu.Lock()
	defer p.mu.Unlock()
	if w, ok := p.cache[k]; ok {
		return w, nil
	}
	w, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(p.directives(k, s.DisabledRules)))
	if err != nil {
		return nil, fmt.Errorf("compile WAF rules: %w", err)
	}
	p.cache[k] = w
	return w, nil
}

// ValidateRules compiles rules alone to report syntax errors before they
// are stored.
func ValidateRules(rules string) error {
	if strings.TrimSpace(rules) == "" {
		return nil
	}
	_, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives("SecRuleEngine On\n" + rules))
	if err != nil {
		return fmt.Errorf("custom_rules: %w", err)
	}
	return nil
}

// Retain drops cached instances not used by sites, after a reload.
func (p *WAFPool) Retain(sites []model.Site, bodyLimit int) {
	keep := map[wafKey]bool{}
	for i := range sites {
		keep[keyFor(&sites[i], bodyLimit)] = true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for k := range p.cache {
		if !keep[k] {
			delete(p.cache, k)
		}
	}
}
