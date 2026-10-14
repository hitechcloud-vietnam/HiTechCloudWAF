package users

import (
	"path/filepath"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 secret "12345678901234567890".
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestTOTPVectors(t *testing.T) {
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		got, err := TOTPCode(rfcSecret, time.Unix(ts, 0))
		if err != nil || got != want {
			t.Errorf("T=%d: %s, want %s (%v)", ts, got, want, err)
		}
	}
	now := time.Unix(1234567890, 0)
	prev, _ := TOTPCode(rfcSecret, now.Add(-30*time.Second))
	if _, ok := VerifyTOTP(rfcSecret, prev, now); !ok {
		t.Error("previous step not accepted")
	}
	old, _ := TOTPCode(rfcSecret, now.Add(-90*time.Second))
	if _, ok := VerifyTOTP(rfcSecret, old, now); ok {
		t.Error("code from 90s ago accepted")
	}
}

func newStore(t *testing.T) (*Store, *time.Time) {
	s, err := Open(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	return s, &now
}

func TestLoginRolesAndTOTP(t *testing.T) {
	s, now := newStore(t)
	if err := s.Create("anh", "short", RoleAdmin); err == nil {
		t.Fatal("short password accepted")
	}
	if err := s.Create("anh", "Mat-khau-dai-2026", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Login("anh", "wrong-password", ""); err != ErrBadLogin {
		t.Fatalf("wrong password: %v", err)
	}
	if _, _, err := s.Login("nobody", "Mat-khau-dai-2026", ""); err != ErrBadLogin {
		t.Fatalf("unknown user: %v", err)
	}
	tok, sess, err := s.Login("anh", "Mat-khau-dai-2026", "")
	if err != nil || sess.Role != RoleAdmin {
		t.Fatal(err)
	}
	if got, ok := s.Session(tok); !ok || got.Username != "anh" {
		t.Fatal("session lookup")
	}

	// Enrol TOTP.
	secret, _ := s.BeginTOTP("anh")
	if err := s.ConfirmTOTP("anh", "000000"); err == nil {
		t.Fatal("wrong confirmation code accepted")
	}
	code, _ := TOTPCode(secret, *now)
	if err := s.ConfirmTOTP("anh", code); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Login("anh", "Mat-khau-dai-2026", ""); err != ErrOTPRequired {
		t.Fatalf("otp not required: %v", err)
	}
	// The code used to confirm cannot be replayed.
	if _, _, err := s.Login("anh", "Mat-khau-dai-2026", code); err != ErrBadOTP {
		t.Fatalf("replayed code: %v", err)
	}
	*now = now.Add(30 * time.Second)
	code, _ = TOTPCode(secret, *now)
	if _, _, err := s.Login("anh", "Mat-khau-dai-2026", code); err != nil {
		t.Fatalf("valid code: %v", err)
	}

	// Sessions expire.
	*now = now.Add(13 * time.Hour)
	if _, ok := s.Session(tok); ok {
		t.Fatal("expired session still valid")
	}
}

func TestLastAdminAndPersistence(t *testing.T) {
	s, _ := newStore(t)
	_ = s.Create("admin1", "Mat-khau-dai-2026", RoleAdmin)
	_ = s.Create("viewer1", "Mat-khau-dai-2026", RoleViewer)
	if err := s.Delete("admin1"); err != ErrLastAdmin {
		t.Fatalf("deleted last admin: %v", err)
	}
	if err := s.Update("admin1", "", RoleViewer, false); err != ErrLastAdmin {
		t.Fatalf("demoted last admin: %v", err)
	}
	tok, _, _ := s.Login("viewer1", "Mat-khau-dai-2026", "")
	if err := s.Update("viewer1", "Mat-khau-moi-2026!", "", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Session(tok); ok {
		t.Fatal("session survived a password change")
	}
	s2, err := Open(s.path)
	if err != nil || len(s2.List()) != 2 || s2.List()[0].Username != "admin1" {
		t.Fatalf("reload: %v %+v", err, s2.List())
	}
	if _, _, err := s2.Login("viewer1", "Mat-khau-moi-2026!", ""); err != nil {
		t.Fatal(err)
	}
}
