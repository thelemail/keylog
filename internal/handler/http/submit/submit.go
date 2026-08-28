package submit

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/thelemail/keylog/internal/entity"
	"github.com/thelemail/keylog/internal/service"
)

type Handler struct {
	svc          service.Log
	tokens       [][32]byte
	maxBodyBytes int64
}

func New(svc service.Log, tokens []string, maxBodyBytes int64) *Handler {
	h := &Handler{svc: svc, maxBodyBytes: maxBodyBytes}
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		h.tokens = append(h.tokens, sha256.Sum256([]byte(t)))
	}
	return h
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/submit", h.submit)
}

type request struct {
	Label    string `json:"label"`
	Record   []byte `json:"record"`
	Metadata []byte `json:"metadata"`
}

type response struct {
	Index     int64  `json:"index"`
	Leaf      []byte `json:"leaf"`
	VRFProof  []byte `json:"vrfProof"`
	Duplicate bool   `json:"duplicate"`
}

func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	if !h.authorised(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req request
	if err := json.NewDecoder(io.LimitReader(r.Body, h.maxBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	receipt, err := h.svc.Submit(r.Context(), entity.Submission{
		Label:    req.Label,
		Record:   req.Record,
		Metadata: req.Metadata,
	})
	if err != nil {
		switch {
		case errors.As(err, &validation.Errors{}):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, entity.ErrAppendUnavailable):
			http.Error(w, "log appender unavailable", http.StatusServiceUnavailable)
		default:
			slog.ErrorContext(r.Context(), "submit failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response{
		Index:     receipt.Index,
		Leaf:      receipt.Leaf,
		VRFProof:  receipt.VRFProof,
		Duplicate: receipt.Duplicate,
	})
}

func (h *Handler) authorised(r *http.Request) bool {
	presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(presented)))
	match := 0
	for _, known := range h.tokens {
		match |= subtle.ConstantTimeCompare(sum[:], known[:])
	}
	return match == 1
}
