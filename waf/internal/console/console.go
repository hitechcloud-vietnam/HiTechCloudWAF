// Package console embeds the web management console.
package console

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var files embed.FS

// Handler serves the console. Pages load scripts from the same origin only;
// the API token lives in sessionStorage and is sent per request.
func Handler() http.Handler {
	sub, _ := fs.Sub(files, "static")
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.URL.Path != "/" && r.URL.Path != "/app.js" && r.URL.Path != "/app.css" && r.URL.Path != "/logo.svg" && r.URL.Path != "/mark.svg" {
			r.URL.Path = "/" // single page app
		}
		fileServer.ServeHTTP(w, r)
	})
}
