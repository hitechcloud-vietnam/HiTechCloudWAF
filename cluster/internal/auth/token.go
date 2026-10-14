// Package auth implements the bearer-token checks used between cluster
// components.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
		Unauthorized(w)
	})
}

// Unauthorized writes the 401 answer of a missing or wrong token.
func Unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="hitechcloud-waf-cluster"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
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

// NewCredential returns a random credential "<prefix>_<id>_<secret>": a
// 64-bit public id used to look the credential up, and a 256-bit secret.
// Only Hash(token) needs to be stored.
func NewCredential(prefix string) (id, token string, err error) {
	b := make([]byte, 8+32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	id = hex.EncodeToString(b[:8])
	return id, prefix + "_" + id + "_" + hex.EncodeToString(b[8:]), nil
}

// CredentialID returns the id of a credential made by NewCredential with
// prefix, or false when token does not have that shape.
func CredentialID(prefix, token string) (string, bool) {
	rest, ok := strings.CutPrefix(token, prefix+"_")
	if !ok {
		return "", false
	}
	id, secret, ok := strings.Cut(rest, "_")
	if !ok || len(id) != 16 || len(secret) != 64 || !isHex(id) || !isHex(secret) {
		return "", false
	}
	return id, true
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// Hash is the hex SHA-256 of a credential. A plain hash is enough for random
// 256-bit secrets: there is no dictionary to attack.
func Hash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// HashMatches reports in constant time whether token hashes to hash. An
// empty hash never matches.
func HashMatches(hash, token string) bool {
	got := Hash(token)
	return hash != "" && subtle.ConstantTimeCompare([]byte(hash), []byte(got)) == 1
}
