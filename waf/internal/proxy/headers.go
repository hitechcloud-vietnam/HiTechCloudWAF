package proxy

import (
	"net/http"
	"net/http/httputil"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

// serverHeaders reveal the upstream software; hide_server_headers strips them.
var serverHeaders = []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"}

// applyHeaderRules runs set/add/remove rules in order. Names were validated
// and canonicalised by model.Site.Normalize.
func applyHeaderRules(h http.Header, rules []model.HeaderRule) {
	for _, r := range rules {
		switch r.Action {
		case model.HeaderSet:
			h.Set(r.Name, r.Value)
		case model.HeaderAdd:
			h.Add(r.Name, r.Value)
		case model.HeaderRemove:
			h.Del(r.Name)
		}
	}
}

// rewriteRequest applies request_headers to a request going upstream.
func (s *siteRT) rewriteRequest(pr *httputil.ProxyRequest) {
	applyHeaderRules(pr.Out.Header, s.site.RequestHeaders)
}

// rewriteResponse strips server banners and applies response_headers.
func (s *siteRT) rewriteResponse(resp *http.Response) {
	if s.site.HideServerHeaders {
		for _, k := range serverHeaders {
			resp.Header.Del(k)
		}
	}
	applyHeaderRules(resp.Header, s.site.ResponseHeaders)
}

// addStickyCookie hands out the sticky-session cookie of a request that was
// (re)assigned.
func (s *siteRT) addStickyCookie(resp *http.Response) {
	if resp.Request == nil || s.lb == nil {
		return
	}
	ctx := resp.Request.Context()
	if id, _ := ctx.Value(stickyKey{}).(string); id != "" {
		v, _ := ctx.Value(ctxKey{}).(ctxVal)
		resp.Header.Add("Set-Cookie", s.lb.stickyCookie(id, v.tls))
	}
}
