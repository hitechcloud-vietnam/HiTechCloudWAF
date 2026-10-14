// Package store persists sites and certificates to a JSON file and notifies
// the runtime when they change.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

// ErrNotFound is returned for unknown IDs.
var ErrNotFound = errors.New("not found")

type state struct {
	NextID int                 `json:"next_id"`
	Sites  map[int]*model.Site `json:"sites"`
	Certs  map[int]*model.Cert `json:"certs"`
}

// Store is safe for concurrent use.
type Store struct {
	mu       sync.RWMutex
	path     string
	st       state
	onChange func()
}

// Open loads path (created on first save).
func Open(path string) (*Store, error) {
	s := &Store{path: path, st: state{NextID: 0, Sites: map[int]*model.Site{}, Certs: map[int]*model.Cert{}}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if s.st.Sites == nil {
		s.st.Sites = map[int]*model.Site{}
	}
	if s.st.Certs == nil {
		s.st.Certs = map[int]*model.Cert{}
	}
	return s, nil
}

// OnChange registers the callback run after every successful write.
func (s *Store) OnChange(f func()) { s.onChange = f }

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.st, "", "  ")
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

func (s *Store) commit() error {
	err := s.saveLocked()
	if err == nil && s.onChange != nil {
		defer s.onChange()
	}
	s.mu.Unlock()
	return err
}

// Sites returns copies sorted by ID.
func (s *Store) Sites() []model.Site {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Site, 0, len(s.st.Sites))
	for _, v := range s.st.Sites {
		c := *v
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Certs returns copies sorted by ID.
func (s *Store) Certs() []model.Cert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Cert, 0, len(s.st.Certs))
	for _, v := range s.st.Certs {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Cert returns one certificate.
func (s *Store) Cert(id int) (model.Cert, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.st.Certs[id]
	if !ok {
		return model.Cert{}, false
	}
	return *c, true
}

// checkConflicts rejects two sites claiming the same name on the same port.
func (s *Store) checkConflictsLocked(site *model.Site) error {
	for _, o := range s.st.Sites {
		if o.ID == site.ID {
			continue
		}
		for _, p := range site.Ports {
			for _, op := range o.Ports {
				if trimSSL(p) != trimSSL(op) {
					continue
				}
				if p != op {
					return fmt.Errorf("port %s is used with a different TLS setting by site %d", trimSSL(p), o.ID)
				}
				for _, n := range site.ServerNames {
					for _, on := range o.ServerNames {
						if n == on {
							return fmt.Errorf("server name %s on port %s already belongs to site %d", n, p, o.ID)
						}
					}
				}
			}
		}
	}
	if site.CertID != 0 {
		if _, ok := s.st.Certs[site.CertID]; !ok {
			return fmt.Errorf("cert_id %d does not exist", site.CertID)
		}
	}
	return nil
}

func trimSSL(p string) string {
	n, _, _ := model.ParsePort(p)
	return fmt.Sprint(n)
}

// CreateSite validates and stores a new site.
func (s *Store) CreateSite(site model.Site) (model.Site, error) {
	if err := site.Normalize(); err != nil {
		return model.Site{}, err
	}
	s.mu.Lock()
	s.st.NextID++
	site.ID = s.st.NextID
	if err := s.checkConflictsLocked(&site); err != nil {
		s.st.NextID--
		s.mu.Unlock()
		return model.Site{}, err
	}
	now := time.Now().UTC()
	site.CreatedAt, site.UpdatedAt = now, now
	c := site
	s.st.Sites[site.ID] = &c
	return site, s.commit()
}

// UpdateSite replaces a site.
func (s *Store) UpdateSite(site model.Site) (model.Site, error) {
	if err := site.Normalize(); err != nil {
		return model.Site{}, err
	}
	s.mu.Lock()
	old, ok := s.st.Sites[site.ID]
	if !ok {
		s.mu.Unlock()
		return model.Site{}, ErrNotFound
	}
	if err := s.checkConflictsLocked(&site); err != nil {
		s.mu.Unlock()
		return model.Site{}, err
	}
	site.CreatedAt, site.UpdatedAt = old.CreatedAt, time.Now().UTC()
	c := site
	s.st.Sites[site.ID] = &c
	return site, s.commit()
}

// DeleteSites removes sites.
func (s *Store) DeleteSites(ids []int) error {
	s.mu.Lock()
	for _, id := range ids {
		if _, ok := s.st.Sites[id]; !ok {
			s.mu.Unlock()
			return fmt.Errorf("site %d: %w", id, ErrNotFound)
		}
	}
	for _, id := range ids {
		delete(s.st.Sites, id)
	}
	return s.commit()
}

// CreateCert stores a certificate.
func (s *Store) CreateCert(c model.Cert) (model.Cert, error) {
	if err := c.Normalize(); err != nil {
		return model.Cert{}, err
	}
	s.mu.Lock()
	s.st.NextID++
	c.ID = s.st.NextID
	now := time.Now().UTC()
	c.CreatedAt, c.UpdatedAt = now, now
	cc := c
	s.st.Certs[c.ID] = &cc
	return c, s.commit()
}

// UpdateCert replaces a certificate.
func (s *Store) UpdateCert(c model.Cert) (model.Cert, error) {
	if err := c.Normalize(); err != nil {
		return model.Cert{}, err
	}
	s.mu.Lock()
	old, ok := s.st.Certs[c.ID]
	if !ok {
		s.mu.Unlock()
		return model.Cert{}, ErrNotFound
	}
	c.CreatedAt, c.UpdatedAt = old.CreatedAt, time.Now().UTC()
	cc := c
	s.st.Certs[c.ID] = &cc
	return c, s.commit()
}

// DeleteCerts removes certificates that no site uses.
func (s *Store) DeleteCerts(ids []int) error {
	s.mu.Lock()
	for _, id := range ids {
		if _, ok := s.st.Certs[id]; !ok {
			s.mu.Unlock()
			return fmt.Errorf("cert %d: %w", id, ErrNotFound)
		}
		for _, site := range s.st.Sites {
			if site.CertID == id {
				s.mu.Unlock()
				return fmt.Errorf("cert %d is used by site %d", id, site.ID)
			}
		}
	}
	for _, id := range ids {
		delete(s.st.Certs, id)
	}
	return s.commit()
}
