package controller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/auth"
)

// sharedTokenWarnEvery limits the deprecation warning to once per node and
// period.
const sharedTokenWarnEvery = time.Hour

type identityKey struct{}

// nodeIdentity is the caller of a node route: an enrolled node (cred set)
// or any holder of the shared node token (cred nil).
type nodeIdentity struct {
	cred *nodeCredential
}

func identity(r *http.Request) nodeIdentity {
	id, _ := r.Context().Value(identityKey{}).(nodeIdentity)
	return id
}

// requireNode accepts a node secret, or the shared node token unless
// require_enrollment is set.
func (s *Server) requireNode(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := auth.Bearer(r)
		if c, ok := s.creds.Authenticate(got); ok {
			h(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, nodeIdentity{cred: &c})))
			return
		}
		if !s.cfg.RequireEnrollment && auth.Equal(s.cfg.NodeToken, got) {
			h(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, nodeIdentity{})))
			return
		}
		auth.Unauthorized(w)
	})
}

// warnSharedToken logs the deprecation of the shared node token, at most
// once per node and sharedTokenWarnEvery.
func (s *Server) warnSharedToken(nodeID string) {
	s.warnMu.Lock()
	last, seen := s.warned[nodeID]
	now := time.Now()
	if !seen || now.Sub(last) >= sharedTokenWarnEvery {
		s.warned[nodeID] = now
	}
	s.warnMu.Unlock()
	if !seen || now.Sub(last) >= sharedTokenWarnEvery {
		s.log.Warn("node authenticated with the shared node_token, which is deprecated; enroll it with a one-time token (POST /v1/enroll-tokens) and set require_enrollment: true once every node is enrolled", "node", nodeID)
	}
}

func decodeOptional(w http.ResponseWriter, r *http.Request, v any) bool {
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v)
	if err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return false
	}
	return true
}

func (s *Server) enrollError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errBadEnrollToken):
		auth.Unauthorized(w)
	case errors.Is(err, errNodeIDMismatch):
		http.Error(w, errNodeIDMismatch.Error(), http.StatusForbidden)
	case errors.Is(err, errNodeEnrolled):
		http.Error(w, errNodeEnrolled.Error(), http.StatusConflict)
	case errors.Is(err, errEnrollInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// enroll exchanges a one-time enrollment token (bearer) for a node secret.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req api.EnrollRequest
	if !decodeOptional(w, r, &req) {
		return
	}
	res, err := s.creds.Enroll(auth.Bearer(r), req)
	if err != nil {
		s.log.Warn("enrollment refused", "err", err, "remote", r.RemoteAddr)
		s.enrollError(w, err)
		return
	}
	s.log.Info("node enrolled", "node", res.NodeID, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) createEnrollToken(w http.ResponseWriter, r *http.Request) {
	var req api.EnrollTokenRequest
	if !decodeOptional(w, r, &req) {
		return
	}
	t, err := s.creds.CreateToken(req)
	if err != nil {
		s.enrollError(w, err)
		return
	}
	s.log.Info("enrollment token created", "id", t.ID, "node", t.NodeID, "expires_at", t.ExpiresAt)
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) deleteEnrollToken(w http.ResponseWriter, r *http.Request) {
	if err := s.creds.DeleteToken(r.PathValue("id")); errors.Is(err, os.ErrNotExist) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.Info("enrollment token revoked", "id", r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

// rotateNode issues an enrollment token bound to the node (keeping the pools
// and region of its current secret). The current secret stays valid until
// the token is used, unless revoke_current is set.
func (s *Server) rotateNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req api.RotateRequest
	if !decodeOptional(w, r, &req) {
		return
	}
	cred, enrolled := s.creds.Get(id)
	if _, ok := s.store.Get(id); !ok && !enrolled {
		http.NotFound(w, r)
		return
	}
	tr := api.EnrollTokenRequest{NodeID: id, ExpiresIn: req.ExpiresIn, Comment: req.Comment}
	if enrolled {
		tr.Pools, tr.Region = cred.Pools, cred.Region
	}
	if tr.Comment == "" {
		tr.Comment = "rotate " + id
	}
	t, err := s.creds.CreateToken(tr)
	if err != nil {
		s.enrollError(w, err)
		return
	}
	if req.RevokeCurrent {
		if _, err := s.creds.Revoke(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.log.Info("node secret rotation started", "node", id, "token", t.ID, "revoked_current", req.RevokeCurrent)
	writeJSON(w, http.StatusCreated, t)
}
