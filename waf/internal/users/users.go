// Package users manages console accounts, roles, TOTP two-factor
// authentication and login sessions.
package users

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Roles.
const (
	RoleAdmin  = "admin"  // everything
	RoleViewer = "viewer" // read only
)

var (
	ErrNotFound    = errors.New("user not found")
	ErrBadLogin    = errors.New("wrong username or password")
	ErrOTPRequired = errors.New("two-factor code required")
	ErrBadOTP      = errors.New("wrong two-factor code")
	ErrLastAdmin   = errors.New("at least one admin must remain")
)

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9._@-]{3,64}$`)

// User is a stored account. Secrets never leave the package through the
// API: use Public.
type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Role         string    `json:"role"`
	TOTPSecret   string    `json:"totp_secret,omitempty"`
	TOTPPending  string    `json:"totp_pending,omitempty"`
	LastOTPStep  uint64    `json:"last_otp_step,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login,omitempty"`
}

// PublicUser is what the API returns.
type PublicUser struct {
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	TOTP      bool      `json:"totp"`
	CreatedAt time.Time `json:"created_at"`
	LastLogin time.Time `json:"last_login,omitempty"`
}

// Public strips secrets.
func (u *User) Public() PublicUser {
	return PublicUser{Username: u.Username, Role: u.Role, TOTP: u.TOTPSecret != "", CreatedAt: u.CreatedAt, LastLogin: u.LastLogin}
}

// Session is a logged-in console user.
type Session struct {
	Username string
	Role     string
	Expires  time.Time
}

// Store keeps users on disk and sessions in memory.
type Store struct {
	mu       sync.Mutex
	path     string
	users    map[string]*User
	sessions map[string]*Session // key: sha256(token)
	ttl      time.Duration
	now      func() time.Time
}

// Open loads path.
func Open(path string) (*Store, error) {
	s := &Store{path: path, users: map[string]*User{}, sessions: map[string]*Session{}, ttl: 12 * time.Hour, now: time.Now}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var list []*User
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, u := range list {
		s.users[u.Username] = u
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	list := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Username < list[j].Username })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func checkPassword(p string) error {
	if len(p) < 10 || len(p) > 72 {
		return errors.New("password must be 10..72 characters")
	}
	return nil
}

func checkRole(r string) error {
	if r != RoleAdmin && r != RoleViewer {
		return errors.New("role must be admin or viewer")
	}
	return nil
}

// List returns public views of all users.
func (s *Store) List() []PublicUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PublicUser, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u.Public())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// Count returns the number of users.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.users)
}

// Create adds a user.
func (s *Store) Create(username, password, role string) error {
	if !nameRe.MatchString(username) {
		return errors.New("username must be 3..64 characters of letters, digits, . _ @ -")
	}
	if err := checkPassword(password); err != nil {
		return err
	}
	if err := checkRole(role); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; ok {
		return fmt.Errorf("user %s already exists", username)
	}
	s.users[username] = &User{Username: username, PasswordHash: string(h), Role: role, CreatedAt: s.now().UTC()}
	return s.saveLocked()
}

func (s *Store) adminsLocked() int {
	n := 0
	for _, u := range s.users {
		if u.Role == RoleAdmin {
			n++
		}
	}
	return n
}

// Update changes role and/or password (empty = unchanged); resetTOTP
// removes two-factor so a user who lost their phone can enrol again.
func (s *Store) Update(username, password, role string, resetTOTP bool) error {
	var hash []byte
	if password != "" {
		if err := checkPassword(password); err != nil {
			return err
		}
		var err error
		if hash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost); err != nil {
			return err
		}
	}
	if role != "" {
		if err := checkRole(role); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return ErrNotFound
	}
	if role != "" && role != u.Role && u.Role == RoleAdmin && s.adminsLocked() == 1 {
		return ErrLastAdmin
	}
	if hash != nil {
		u.PasswordHash = string(hash)
	}
	if role != "" {
		u.Role = role
	}
	if resetTOTP {
		u.TOTPSecret, u.TOTPPending = "", ""
	}
	if hash != nil || role != "" || resetTOTP {
		s.dropSessionsLocked(username)
	}
	return s.saveLocked()
}

// Delete removes a user and their sessions.
func (s *Store) Delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return ErrNotFound
	}
	if u.Role == RoleAdmin && s.adminsLocked() == 1 {
		return ErrLastAdmin
	}
	delete(s.users, username)
	s.dropSessionsLocked(username)
	return s.saveLocked()
}

func (s *Store) dropSessionsLocked(username string) {
	for k, sess := range s.sessions {
		if sess.Username == username {
			delete(s.sessions, k)
		}
	}
}

var (
	dummyOnce sync.Once
	dummy     string
)

func dummyHash() string {
	dummyOnce.Do(func() {
		h, _ := bcrypt.GenerateFromPassword([]byte("hcw-dummy-password-for-timing"), bcrypt.DefaultCost)
		dummy = string(h)
	})
	return dummy
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// Login checks credentials (and the TOTP code when enrolled) and returns a
// new session token.
func (s *Store) Login(username, password, otp string) (string, *Session, error) {
	s.mu.Lock()
	u, ok := s.users[username]
	// Compare against a dummy hash when the user is unknown so timing does
	// not reveal which usernames exist.
	hash := dummyHash()
	if ok {
		hash = u.PasswordHash
	}
	s.mu.Unlock()
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil || !ok {
		return "", nil, ErrBadLogin
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.users[username] != u || u.PasswordHash != hash {
		return "", nil, ErrBadLogin // changed or deleted meanwhile
	}
	if u.TOTPSecret != "" {
		if otp == "" {
			return "", nil, ErrOTPRequired
		}
		step, ok := VerifyTOTP(u.TOTPSecret, otp, s.now())
		if !ok || step <= u.LastOTPStep {
			return "", nil, ErrBadOTP
		}
		u.LastOTPStep = step
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	sess := &Session{Username: u.Username, Role: u.Role, Expires: s.now().Add(s.ttl)}
	s.sessions[hashToken(tok)] = sess
	u.LastLogin = s.now().UTC()
	_ = s.saveLocked()
	c := *sess
	return tok, &c, nil
}

// Session resolves a token; expired sessions are removed.
func (s *Store) Session(token string) (*Session, bool) {
	if token == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := hashToken(token)
	sess, ok := s.sessions[k]
	if !ok {
		return nil, false
	}
	if s.now().After(sess.Expires) {
		delete(s.sessions, k)
		return nil, false
	}
	c := *sess
	return &c, true
}

// Logout ends a session.
func (s *Store) Logout(token string) {
	s.mu.Lock()
	delete(s.sessions, hashToken(token))
	s.mu.Unlock()
}

// BeginTOTP stores a pending secret for username and returns it.
func (s *Store) BeginTOTP(username string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return "", ErrNotFound
	}
	u.TOTPPending = NewTOTPSecret()
	return u.TOTPPending, s.saveLocked()
}

// ConfirmTOTP enables the pending secret when code matches it.
func (s *Store) ConfirmTOTP(username, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return ErrNotFound
	}
	if u.TOTPPending == "" {
		return errors.New("start the two-factor setup first")
	}
	step, ok := VerifyTOTP(u.TOTPPending, code, s.now())
	if !ok {
		return ErrBadOTP
	}
	u.TOTPSecret, u.TOTPPending, u.LastOTPStep = u.TOTPPending, "", step
	return s.saveLocked()
}

// DisableTOTP turns two-factor off after checking a current code.
func (s *Store) DisableTOTP(username, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return ErrNotFound
	}
	if u.TOTPSecret == "" {
		return nil
	}
	step, ok := VerifyTOTP(u.TOTPSecret, code, s.now())
	if !ok || step <= u.LastOTPStep {
		return ErrBadOTP
	}
	u.TOTPSecret, u.LastOTPStep = "", step
	return s.saveLocked()
}

// ChangePassword lets a user change their own password.
// Every other session of the user is ended; keepToken (the caller's own
// session, may be empty) stays valid.
func (s *Store) ChangePassword(username, current, next, keepToken string) error {
	s.mu.Lock()
	u, ok := s.users[username]
	hash := ""
	if ok {
		hash = u.PasswordHash
	}
	s.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(current)) != nil {
		return ErrBadLogin
	}
	if err := checkPassword(next); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.users[username] != u || u.PasswordHash != hash {
		return ErrBadLogin
	}
	u.PasswordHash = string(h)
	keep, had := s.sessions[hashToken(keepToken)]
	s.dropSessionsLocked(username)
	if had && keep.Username == username {
		s.sessions[hashToken(keepToken)] = keep
	}
	return s.saveLocked()
}
