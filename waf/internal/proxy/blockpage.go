package proxy

import (
	"html/template"
	"net/http"
)

// Brand customises the page shown to blocked visitors.
type Brand struct {
	Name       string `yaml:"name" json:"name"`
	Color      string `yaml:"color" json:"color"`
	SupportURL string `yaml:"support_url" json:"support_url"`
}

var blockTmpl = template.Must(template.New("block").Parse(`<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} – {{.Brand.Name}}</title>
<style>
:root{--brand:{{.Brand.Color}};--bg:#f8fafc;--card:#fff;--text:#0f172a;--muted:#64748b}
@media (prefers-color-scheme:dark){:root{--bg:#0b1220;--card:#111a2e;--text:#e2e8f0;--muted:#94a3b8}}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);font-family:Inter,"Segoe UI",system-ui,sans-serif}
.c{max-width:520px;margin:16px;padding:32px;background:var(--card);border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.08);text-align:center}
.s{width:64px;height:64px;margin:0 auto 16px;border-radius:50%;background:var(--brand);display:flex;align-items:center;justify-content:center;color:#fff;font-size:30px;font-weight:700}
h1{font-size:22px;margin:0 0 8px}p{color:var(--muted);line-height:1.5;margin:6px 0}code{font-size:13px}
a{color:var(--brand)}
</style></head><body><div class="c">
<div class="s">!</div>
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
<p>Mã sự kiện / Event ID: <code>{{.EventID}}</code></p>
{{if .Brand.SupportURL}}<p><a href="{{.Brand.SupportURL}}" rel="noopener">Liên hệ hỗ trợ</a></p>{{end}}
<p style="font-size:12px;margin-top:18px">Protected by {{.Brand.Name}}</p>
</div></body></html>`))

type blockData struct {
	Brand          Brand
	Title, Message string
	EventID        string
}

func writeBlock(w http.ResponseWriter, b Brand, status int, eventID string) {
	d := blockData{Brand: b, EventID: eventID}
	switch status {
	case http.StatusTooManyRequests:
		d.Title, d.Message = "Truy cập quá nhanh", "Bạn đã gửi quá nhiều yêu cầu. Vui lòng thử lại sau ít phút. / Too many requests, please retry later."
		w.Header().Set("Retry-After", "60")
	default:
		d.Title, d.Message = "Yêu cầu bị chặn", "Yêu cầu của bạn bị hệ thống bảo mật chặn lại. / Your request was blocked by the web application firewall."
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-HCW-Event-ID", eventID)
	w.WriteHeader(status)
	_ = blockTmpl.Execute(w, d)
}
