package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func get(t *testing.T, h *Handler) *httptest.ResponseRecorder {
	t.Helper()
	r := chi.NewRouter()
	h.Mount(r)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	return rec
}

func up(context.Context) error { return nil }

func TestHealthReportsEachComponent(t *testing.T) {
	rec := get(t, New(time.Second, map[string]Check{"database": up, "tiles": up}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	want := `{"status":"up","components":{"database":"up","tiles":"up"}}`
	if got := strings.TrimSpace(rec.Body.String()); got != want {
		t.Fatalf("body %s, want %s", got, want)
	}
}

func TestHealthIsDownWithoutLeakingTheError(t *testing.T) {
	failing := func(context.Context) error {
		return errors.New("dial tcp postgres.keylog.svc:5432: connection refused")
	}
	rec := get(t, New(time.Second, map[string]Check{"database": failing, "tiles": up}))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", rec.Code)
	}
	want := `{"status":"down","components":{"database":"down","tiles":"up"}}`
	if got := strings.TrimSpace(rec.Body.String()); got != want {
		t.Fatalf("body %s, want %s", got, want)
	}
}

func TestHealthGivesUpOnAHangingCheck(t *testing.T) {
	hanging := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	start := time.Now()
	rec := get(t, New(50*time.Millisecond, map[string]Check{"database": hanging}))
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("took %s", elapsed)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", rec.Code)
	}
}
