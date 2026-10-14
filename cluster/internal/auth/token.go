// Package auth implements the bearer-token checks used between cluster
// components.
package auth

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// Equal compares two secrets in constant time. An empty expected secret never
// matches, so a missing configuration fails closed.
func Equal(expected, got string) bool {
	if expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(got)) == 1
}

// Bearer extracts the token of an "Authorization: Bearer <token>" header.
func Bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

// Require wraps h so it only runs when the request carries one of tokens.
func Require(h http.Handler, tokens ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := Bearer(r)
		for _, t := range tokens {
			if Equal(t, got) {
				h.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="hitechcloud-waf-cluster"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// Resolve returns value, or the trimmed content of file when value is empty.
// Secrets are normally kept in files so they stay out of process listings and
// config repositories.
func Resolve(value, file string) (string, error) {
	if value != "" || file == "" {
		return value, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("read secret file %s: %w", file, err)
	}
	return strings.TrimSpace(string(b)), nil
}
