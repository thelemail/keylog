package log

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thelemail/keylog/internal/entity"
	"github.com/thelemail/keylog/internal/repository"
	"github.com/thelemail/keylog/pkg/tlogproof"
)

type stubService struct {
	history  entity.History
	err      error
	proof    []byte
	proofErr error
}

func (s *stubService) Submit(context.Context, entity.Submission) (entity.Receipt, error) {
	return entity.Receipt{}, nil
}

func (s *stubService) SweepPending(context.Context) (int, error) { return 0, nil }

func (s *stubService) Proof(_ context.Context, index int64) ([]byte, error) {
	if s.proofErr != nil {
		return nil, s.proofErr
	}
	if index != 7 {
		return nil, repository.ErrEntryNotFound
	}
	return s.proof, nil
}

func (s *stubService) History(_ context.Context, label string) (entity.History, error) {
	if s.err != nil {
		return entity.History{}, s.err
	}
	if label != s.history.Label {
		return entity.History{}, entity.ErrEntryNotFound
	}
	return s.history, nil
}

func newTestServer(t *testing.T, svc *stubService) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte("test.thelemail.com/keys\n3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "tile", "0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tile", "0", "000"), []byte("tile-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	New(svc, dir).Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, dir
}

func get(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestReadAPIIsServedAtTheRoot(t *testing.T) {
	srv, _ := newTestServer(t, &stubService{})

	checkpoint := get(t, srv.URL+"/checkpoint")
	if checkpoint.StatusCode != http.StatusOK {
		t.Fatalf("checkpoint status = %d, want 200", checkpoint.StatusCode)
	}
	if got := checkpoint.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("checkpoint Cache-Control = %q, want no-store", got)
	}
	if got := checkpoint.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("checkpoint CORS header = %q, want *", got)
	}

	tile := get(t, srv.URL+"/tile/0/000")
	if tile.StatusCode != http.StatusOK {
		t.Fatalf("tile status = %d, want 200", tile.StatusCode)
	}
	if got := tile.Header.Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("tile Cache-Control = %q", got)
	}
}

func TestPartialTilesAreNotCached(t *testing.T) {
	srv, dir := newTestServer(t, &stubService{})
	if err := os.MkdirAll(filepath.Join(dir, "tile", "0", "000.p"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tile", "0", "000.p", "1"), []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}

	resp := get(t, srv.URL+"/tile/0/000.p/1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("partial tile Cache-Control = %q, want no-store", got)
	}
}

func TestMonitorReturnsTheLoggedHistory(t *testing.T) {
	index := int64(7)
	includedAt := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	srv, _ := newTestServer(t, &stubService{history: entity.History{
		Label:    "vlad@thelemail.com",
		VRFProof: []byte("pi"),
		Entries: []entity.Entry{{
			Record:     []byte(`{"v":1}`),
			Metadata:   []byte("sig"),
			Index:      &index,
			IncludedAt: &includedAt,
		}},
	}})

	resp := get(t, srv.URL+"/monitor?label=vlad@thelemail.com")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got monitorResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Label != "vlad@thelemail.com" || string(got.VRFProof) != "pi" {
		t.Fatalf("response = %+v", got)
	}
	if len(got.Entries) != 1 || got.Entries[0].Index != 7 || string(got.Entries[0].Record) != `{"v":1}` {
		t.Fatalf("entries = %+v", got.Entries)
	}
}

func TestMonitorRejectsAMissingLabel(t *testing.T) {
	srv, _ := newTestServer(t, &stubService{})

	if resp := get(t, srv.URL+"/monitor"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if resp := get(t, srv.URL+"/monitor?label=nobody@thelemail.com"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestProofIsServedByIndex(t *testing.T) {
	srv, _ := newTestServer(t, &stubService{proof: []byte("c2sp.org/tlog-proof@v1\n")})

	resp := get(t, srv.URL+"/proof?index=7")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "c2sp.org/tlog-proof@v1\n" {
		t.Fatalf("body = %q", body)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestProofRejectsABadIndex(t *testing.T) {
	srv, _ := newTestServer(t, &stubService{proof: []byte("proof")})

	for _, q := range []string{"", "?index=", "?index=abc", "?index=-1"} {
		if resp := get(t, srv.URL+"/proof"+q); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("index %q: status = %d, want 400", q, resp.StatusCode)
		}
	}
	if resp := get(t, srv.URL+"/proof?index=99"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestProofReports404WhileTheCheckpointIsBehind(t *testing.T) {
	srv, _ := newTestServer(t, &stubService{proofErr: tlogproof.ErrCheckpointBehind})

	if resp := get(t, srv.URL+"/proof?index=7"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}
