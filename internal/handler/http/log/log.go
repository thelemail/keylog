package log

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thelemail/keylog/internal/entity"
	"github.com/thelemail/keylog/internal/repository"
	"github.com/thelemail/keylog/internal/service"
	"github.com/thelemail/keylog/pkg/tlogproof"
)

type Handler struct {
	svc   service.Log
	files http.Handler
}

func New(svc service.Log, logPath string) *Handler {
	return &Handler{
		svc:   svc,
		files: http.FileServer(http.Dir(logPath)),
	}
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/checkpoint", h.serveFile)
	r.Get("/tile/*", h.serveFile)
	r.Get("/proof", h.proof)
	r.Get("/monitor", h.monitor)
}

func (h *Handler) serveFile(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "checkpoint" || strings.Contains(path, ".p/") {
		w.Header().Set("Cache-Control", "no-store")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	h.files.ServeHTTP(w, r)
}

func (h *Handler) proof(w http.ResponseWriter, r *http.Request) {
	index, err := strconv.ParseInt(r.URL.Query().Get("index"), 10, 64)
	if err != nil || index < 0 {
		http.Error(w, "index must be a non-negative integer", http.StatusBadRequest)
		return
	}
	proof, err := h.svc.Proof(r.Context(), index)
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrEntryNotFound), errors.Is(err, tlogproof.ErrCheckpointBehind):
			http.NotFound(w, r)
		case errors.Is(err, entity.ErrProofsUnavailable):
			http.Error(w, "proofs unavailable", http.StatusServiceUnavailable)
		default:
			slog.ErrorContext(r.Context(), "build proof", "index", index, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_, _ = w.Write(proof)
}

type monitorEntry struct {
	Index      int64     `json:"index"`
	Record     []byte    `json:"record"`
	Metadata   []byte    `json:"metadata,omitempty"`
	IncludedAt time.Time `json:"includedAt"`
}

type monitorResponse struct {
	Label    string         `json:"label"`
	VRFProof []byte         `json:"vrfProof"`
	Entries  []monitorEntry `json:"entries"`
}

func (h *Handler) monitor(w http.ResponseWriter, r *http.Request) {
	label := strings.TrimSpace(r.URL.Query().Get("label"))
	if label == "" {
		http.Error(w, "label is required", http.StatusBadRequest)
		return
	}
	history, err := h.svc.History(r.Context(), label)
	if err != nil {
		if errors.Is(err, entity.ErrEntryNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resp := monitorResponse{
		Label:    history.Label,
		VRFProof: history.VRFProof,
		Entries:  make([]monitorEntry, 0, len(history.Entries)),
	}
	for _, e := range history.Entries {
		resp.Entries = append(resp.Entries, monitorEntry{
			Index:      *e.Index,
			Record:     e.Record,
			Metadata:   e.Metadata,
			IncludedAt: *e.IncludedAt,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(resp)
}
