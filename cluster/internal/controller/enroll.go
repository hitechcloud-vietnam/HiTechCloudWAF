package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/auth"
)

// Credential prefixes: "hcwe_<id>_<secret>" for one-time enrollment tokens,
// "hcwn_<id>_<secret>" for node secrets.
const (
	enrollPrefix = "hcwe"
	secretPrefix = "hcwn"

	defaultEnrollTTL = 24 * time.Hour
	maxEnrollTTL     = 30 * 24 * time.Hour
	// Used and expired tokens stay listed this long after they expire.
	keepExpiredTokens = 7 * 24 * time.Hour
)

var (
	errBadEnrollToken = errors.New("invalid, expired or already used enrollment token")
	errEnrollInvalid  = errors.New("invalid enrollment")
	errNodeIDMismatch = errors.New("the enrollment token is bound to another node id")
	errNodeEnrolled   = errors.New("node id already holds an active node secret; revoke it or use a token bound to this id")
)

// enrollRecord is a stored enrollment token: the hash only, never the token.
type enrollRecord struct {
	ID        string     `json:"id"`
	Hash      string     `json:"hash"`
	NodeID    string     `json:"node_id,omitempty"`
	Pools     []string   `json:"pools,omitempty"`
	Region    string     `json:"region,omitempty"`
	Comment   string     `json:"comment,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	UsedBy    string     `json:"used_by,omitempty"`
}

// nodeCredential is the secret of one node. A revoked credential is kept as
// a tombstone: once a node ID has enrolled, the shared node token is never
// accepted for it again.
type nodeCredential struct {
	ID            string     `json:"id"`
	NodeID        string     `json:"node_id"`
	Hash          string     `json:"hash"`
	Pools         []string   `json:"pools,omitempty"`
	Region        string     `json:"region,omitempty"`
	EnrollTokenID string     `json:"enroll_token_id"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

func (c *nodeCredential) active() bool { return c != nil && c.RevokedAt == nil }

type credFile struct {
	EnrollTokens []*enrollRecord   `json:"enroll_tokens"`
	Nodes        []*nodeCredential `json:"node_credentials"`
}

// CredStore holds enrollment tokens and per-node secrets (as SHA-256 hashes),
// persisted to a JSON file readable by its owner only.
type CredStore struct {
	mu     sync.Mutex
	path   string
	now    func() time.Time
	tokens map[string]*enrollRecord   // by token id
	nodes  map[string]*nodeCredential // by node id, latest credential
	byCred map[string]string          // active credential id -> node id
}

// NewCredStore loads path when it exists. An empty path keeps everything in
// memory.
func NewCredStore(path string) (*CredStore, error) {
	s := &CredStore{path: path, now: time.Now, tokens: map[string]*enrollRecord{},
		nodes: map[string]*nodeCredential{}, byCred: map[string]string{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f credFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, t := range f.EnrollTokens {
		s.tokens[t.ID] = t
	}
	for _, c := range f.Nodes {
		s.nodes[c.NodeID] = c
		if c.active() {
			s.byCred[c.ID] = c.NodeID
		}
	}
	return s, nil
}

func (s *CredStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	f := credFile{EnrollTokens: make([]*enrollRecord, 0, len(s.tokens)), Nodes: make([]*nodeCredential, 0, len(s.nodes))}
	for _, t := range s.tokens {
		f.EnrollTokens = append(f.EnrollTokens, t)
	}
	sort.Slice(f.EnrollTokens, func(i, j int) bool { return f.EnrollTokens[i].CreatedAt.Before(f.EnrollTokens[j].CreatedAt) })
	for _, c := range s.nodes {
		f.Nodes = append(f.Nodes, c)
	}
	sort.Slice(f.Nodes, func(i, j int) bool { return f.Nodes[i].NodeID < f.Nodes[j].NodeID })
	return writeJSONFile(s.path, f)
}

func (s *CredStore) view(t *enrollRecord) api.EnrollToken {
	v := api.EnrollToken{ID: t.ID, NodeID: t.NodeID, Pools: slices.Clone(t.Pools), Region: t.Region, Comment: t.Comment,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, UsedAt: t.UsedAt, UsedBy: t.UsedBy, Status: "active"}
	switch {
	case t.UsedAt != nil:
		v.Status = "used"
	case !s.now().Before(t.ExpiresAt):
		v.Status = "expired"
	}
	return v
}

func validateBinding(nodeID string, pools []string, region string) error {
	if nodeID != "" && !idPattern.MatchString(nodeID) {
		return fmt.Errorf("%w: invalid node_id", errEnrollInvalid)
	}
	for _, p := range pools {
		if !idPattern.MatchString(p) {
			return fmt.Errorf("%w: invalid pool name %q", errEnrollInvalid, p)
		}
	}
	if region != "" && !idPattern.MatchString(region) {
		return fmt.Errorf("%w: invalid region", errEnrollInvalid)
	}
	return nil
}

func ttl(seconds int64) (time.Duration, error) {
	if seconds == 0 {
		return defaultEnrollTTL, nil
	}
	d := time.Duration(seconds) * time.Second
	if seconds < 0 || d > maxEnrollTTL {
		return 0, fmt.Errorf("%w: expires_in must be between 1 and %d seconds", errEnrollInvalid, int64(maxEnrollTTL/time.Second))
	}
	return d, nil
}

// CreateToken issues a one-time enrollment token. The returned view is the
// only place the token appears.
func (s *CredStore) CreateToken(req api.EnrollTokenRequest) (api.EnrollToken, error) {
	if err := validateBinding(req.NodeID, req.Pools, req.Region); err != nil {
		return api.EnrollToken{}, err
	}
	if len(req.Comment) > 200 {
		return api.EnrollToken{}, fmt.Errorf("%w: comment is longer than 200 characters", errEnrollInvalid)
	}
	d, err := ttl(req.ExpiresIn)
	if err != nil {
		return api.EnrollToken{}, err
	}
	id, token, err := auth.NewCredential(enrollPrefix)
	if err != nil {
		return api.EnrollToken{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	for k, t := range s.tokens {
		if now.Sub(t.ExpiresAt) > keepExpiredTokens {
			delete(s.tokens, k)
		}
	}
	rec := &enrollRecord{ID: id, Hash: auth.Hash(token), NodeID: req.NodeID, Pools: slices.Clone(req.Pools),
		Region: req.Region, Comment: req.Comment, CreatedAt: now, ExpiresAt: now.Add(d)}
	s.tokens[id] = rec
	if err := s.saveLocked(); err != nil {
		delete(s.tokens, id)
		return api.EnrollToken{}, err
	}
	v := s.view(rec)
	v.Token = token
	return v, nil
}

// ListTokens returns the enrollment tokens, newest first, without secrets.
func (s *CredStore) ListTokens() []api.EnrollToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]api.EnrollToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, s.view(t))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// DeleteToken revokes (removes) an enrollment token. Secrets already issued
// with it stay valid.
func (s *CredStore) DeleteToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return os.ErrNotExist
	}
	delete(s.tokens, id)
	if err := s.saveLocked(); err != nil {
		s.tokens[id] = t
		return err
	}
	return nil
}

// Enroll consumes an enrollment token and returns a new node secret bound to
// the resulting node ID. A token bound to a node ID replaces that node's
// previous secret; an unbound token cannot take over an ID that holds an
// active secret.
func (s *CredStore) Enroll(token string, req api.EnrollRequest) (api.EnrollResponse, error) {
	id, _ := auth.CredentialID(enrollPrefix, token)
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.tokens[id]
	hash := ""
	if rec != nil {
		hash = rec.Hash
	}
	// Always hash and compare, so unknown ids cost the same as wrong secrets.
	if !auth.HashMatches(hash, token) {
		return api.EnrollResponse{}, fmt.Errorf("%w (unknown token)", errBadEnrollToken)
	}
	now := s.now().UTC()
	if rec.UsedAt != nil {
		return api.EnrollResponse{}, fmt.Errorf("%w (token %s already used by %s)", errBadEnrollToken, rec.ID, rec.UsedBy)
	}
	if !now.Before(rec.ExpiresAt) {
		return api.EnrollResponse{}, fmt.Errorf("%w (token %s expired)", errBadEnrollToken, rec.ID)
	}
	nodeID := rec.NodeID
	if req.ID != "" {
		if nodeID != "" && req.ID != nodeID {
			return api.EnrollResponse{}, fmt.Errorf("%w (token %s is for %q, agent asked for %q)", errNodeIDMismatch, rec.ID, nodeID, req.ID)
		}
		nodeID = req.ID
	}
	if nodeID == "" {
		nodeID = strings.ToLower(req.Hostname)
	}
	if !idPattern.MatchString(nodeID) {
		return api.EnrollResponse{}, fmt.Errorf("%w: invalid node id %q", errEnrollInvalid, nodeID)
	}
	prev := s.nodes[nodeID]
	if rec.NodeID == "" && prev.active() {
		return api.EnrollResponse{}, fmt.Errorf("%w (node %s)", errNodeEnrolled, nodeID)
	}
	credID, secret, err := auth.NewCredential(secretPrefix)
	if err != nil {
		return api.EnrollResponse{}, err
	}
	c := &nodeCredential{ID: credID, NodeID: nodeID, Hash: auth.Hash(secret), Pools: slices.Clone(rec.Pools),
		Region: rec.Region, EnrollTokenID: rec.ID, CreatedAt: now}
	rec.UsedAt, rec.UsedBy = &now, nodeID
	if prev.active() {
		delete(s.byCred, prev.ID)
	}
	s.nodes[nodeID] = c
	s.byCred[credID] = nodeID
	if err := s.saveLocked(); err != nil {
		rec.UsedAt, rec.UsedBy = nil, ""
		delete(s.byCred, credID)
		if prev != nil {
			s.nodes[nodeID] = prev
			if prev.active() {
				s.byCred[prev.ID] = nodeID
			}
		} else {
			delete(s.nodes, nodeID)
		}
		return api.EnrollResponse{}, err
	}
	return api.EnrollResponse{NodeID: nodeID, Secret: secret, Pools: slices.Clone(c.Pools), Region: c.Region}, nil
}

// Authenticate returns the active credential that secret belongs to.
func (s *CredStore) Authenticate(secret string) (nodeCredential, bool) {
	id, _ := auth.CredentialID(secretPrefix, secret)
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.nodes[s.byCred[id]]
	hash := ""
	if c.active() && c.ID == id {
		hash = c.Hash
	}
	if !auth.HashMatches(hash, secret) {
		return nodeCredential{}, false
	}
	return *c, true
}

// Get returns the latest credential of nodeID, active or revoked.
func (s *CredStore) Get(nodeID string) (nodeCredential, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.nodes[nodeID]
	if !ok {
		return nodeCredential{}, false
	}
	return *c, true
}

// Revoke invalidates the active secret of nodeID. It reports whether there
// was one.
func (s *CredStore) Revoke(nodeID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.nodes[nodeID]
	if !c.active() {
		return false, nil
	}
	now := s.now().UTC()
	c.RevokedAt = &now
	delete(s.byCred, c.ID)
	if err := s.saveLocked(); err != nil {
		c.RevokedAt = nil
		s.byCred[c.ID] = nodeID
		return false, err
	}
	return true, nil
}
