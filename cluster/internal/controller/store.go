// Package controller implements the HiTechCloud WAF cluster control plane:
// node registry, health checking, configuration snapshots and the admin
// dashboard.
package controller

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
)

// Store is the node registry. It is persisted to a JSON file so drain flags
// and weight overrides survive restarts.
type Store struct {
	mu    sync.RWMutex
	nodes map[string]*api.Node
	path  string
	now   func() time.Time
}

// NewStore loads path when it exists.
func NewStore(path string) (*Store, error) {
	s := &Store{nodes: map[string]*api.Node{}, path: path, now: time.Now}
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
	var list []*api.Node
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	for _, n := range list {
		// Health is never trusted from disk; it must be re-established.
		n.Healthy, n.ProbeOK, n.Reason = false, false, "restored from state, awaiting heartbeat"
		s.nodes[n.ID] = n
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	return writeJSONFile(s.path, s.listLocked())
}

// writeJSONFile replaces path atomically with v as indented JSON.
func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) listLocked() []*api.Node {
	out := make([]*api.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		c := *n
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Heartbeat records a heartbeat. New nodes are persisted immediately.
func (s *Store) Heartbeat(hb api.Heartbeat) (*api.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	n, ok := s.nodes[hb.ID]
	if !ok {
		n = &api.Node{FirstSeen: now}
		s.nodes[hb.ID] = n
	}
	n.Heartbeat = hb
	n.LastSeen = now
	var err error
	if !ok {
		err = s.saveLocked()
	}
	c := *n
	return &c, err
}

// List returns copies of all nodes.
func (s *Store) List() []*api.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listLocked()
}

// Get returns a copy of one node.
func (s *Store) Get(id string) (*api.Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.nodes[id]
	if !ok {
		return nil, false
	}
	c := *n
	return &c, true
}

// Patch applies admin changes.
func (s *Store) Patch(id string, p api.NodePatch) (*api.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[id]
	if !ok {
		return nil, os.ErrNotExist
	}
	if p.Drain != nil {
		n.Drain = *p.Drain
	}
	if p.WeightOverride != nil {
		if *p.WeightOverride < 0 {
			return nil, errors.New("weight_override must be >= 0")
		}
		n.WeightOverride = *p.WeightOverride
	}
	c := *n
	return &c, s.saveLocked()
}

// Delete removes a node.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.nodes[id]; !ok {
		return os.ErrNotExist
	}
	delete(s.nodes, id)
	return s.saveLocked()
}

// SetProbe records an active probe result.
func (s *Store) SetProbe(id string, ok bool, errText string, took time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, found := s.nodes[id]
	if !found {
		return
	}
	n.ProbeOK, n.ProbeError, n.ProbeAt, n.ProbeMillis = ok, errText, s.now().UTC(), took.Milliseconds()
}

// Evaluate recomputes health of all nodes and forgets long-silent ones.
func (s *Store) Evaluate(heartbeatTimeout, forgetAfter time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	changed := false
	for id, n := range s.nodes {
		if forgetAfter > 0 && now.Sub(n.LastSeen) > forgetAfter {
			delete(s.nodes, id)
			changed = true
			continue
		}
		evaluate(n, now, heartbeatTimeout)
	}
	if changed {
		_ = s.saveLocked()
	}
}

// evaluate derives n.Healthy.
func evaluate(n *api.Node, now time.Time, heartbeatTimeout time.Duration) {
	switch {
	case now.Sub(n.LastSeen) > heartbeatTimeout:
		n.Healthy, n.Reason = false, "heartbeat timeout"
	case !n.EngineHealthy:
		n.Healthy, n.Reason = false, "engine unhealthy: "+n.EngineError
	case n.ProbeURL != "" && !n.ProbeOK:
		n.Healthy, n.Reason = false, "probe failed: "+n.ProbeError
	case n.Drain:
		n.Healthy, n.Reason = true, "draining"
	default:
		n.Healthy, n.Reason = true, ""
	}
}

// Endpoints returns the DNS candidates of pool. Drained nodes are excluded.
func (s *Store) Endpoints(pool string) api.PoolEndpoints {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := api.PoolEndpoints{Pool: pool, Endpoints: []api.Endpoint{}}
	for _, n := range s.listLocked() {
		if n.Drain || !inPool(n, pool) {
			continue
		}
		out.Endpoints = append(out.Endpoints, api.Endpoint{
			NodeID: n.ID, Name: n.Name, Region: n.Region,
			IPv4: n.IPv4, IPv6: n.IPv6,
			Weight: n.EffectiveWeight(), Healthy: n.Healthy,
		})
	}
	return out
}

func inPool(n *api.Node, pool string) bool {
	if len(n.Pools) == 0 {
		return pool == "default"
	}
	for _, p := range n.Pools {
		if p == pool {
			return true
		}
	}
	return false
}
