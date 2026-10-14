package users

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP is defined over HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit base32 secret.
func NewTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return b32.EncodeToString(b)
}

// totpCode computes the RFC 6238 code for counter.
func totpCode(secret string, counter uint64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000), nil
}

// TOTPCode returns the code valid at t (used by tests and tools).
func TOTPCode(secret string, t time.Time) (string, error) {
	return totpCode(secret, uint64(t.Unix()/30))
}

// VerifyTOTP accepts the code of the current 30-second step or one step
// either side (clock drift). It returns the matched step so callers can
// refuse replays.
func VerifyTOTP(secret, code string, t time.Time) (uint64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	now := uint64(t.Unix() / 30)
	for _, step := range []uint64{now, now - 1, now + 1} {
		c, err := totpCode(secret, step)
		if err == nil && hmac.Equal([]byte(c), []byte(code)) {
			return step, true
		}
	}
	return 0, false
}

// OTPAuthURL is the provisioning URI shown as a QR code.
func OTPAuthURL(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}
