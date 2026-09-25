package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

type Check func(ctx context.Context) error

type Handler struct {
	checks  map[string]Check
	timeout time.Duration
}

func New(timeout time.Duration, checks map[string]Check) *Handler {
	return &Handler{checks: checks, timeout: timeout}
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/health", h.serve)
}

type report struct {
	Status     string            `json:"status"`
	Components map[string]string `json:"components"`
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	out := report{Status: "up", Components: make(map[string]string, len(h.checks))}
	for name, check := range h.checks {
		if err := check(ctx); err != nil {
			slog.WarnContext(ctx, "health check failed", "check", name, "error", err)
			out.Components[name] = "down"
			out.Status = "down"
			continue
		}
		out.Components[name] = "up"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if out.Status != "up" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(out)
}
