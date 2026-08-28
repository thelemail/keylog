package submit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/thelemail/keylog/internal/entity"
)

type stubService struct {
	called  bool
	receipt entity.Receipt
	err     error
}

func (s *stubService) Submit(_ context.Context, _ entity.Submission) (entity.Receipt, error) {
	s.called = true
	return s.receipt, s.err
}

func (s *stubService) SweepPending(context.Context) (int, error) { return 0, nil }

func (s *stubService) Proof(context.Context, int64) ([]byte, error) { return nil, nil }

func (s *stubService) History(context.Context, string) (entity.History, error) {
	return entity.History{}, entity.ErrEntryNotFound
}

func newTestServer(t *testing.T, svc *stubService, tokens []string) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	New(svc, tokens, 65536).Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, url, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+"/submit", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestSubmitRequiresAValidToken(t *testing.T) {
	svc := &stubService{}
	srv := newTestServer(t, svc, []string{"correct-token"})
	body := `{"label":"vlad@thelemail.com","record":"eyJ2IjoxfQ=="}`

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"no token", ""},
		{"wrong token", "wrong-token"},
		{"token prefix", "correct"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := post(t, srv.URL, tc.token, body)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if svc.called {
				t.Fatal("service was reached without a valid token")
			}
		})
	}
}

func TestSubmitReturnsTheReceipt(t *testing.T) {
	svc := &stubService{receipt: entity.Receipt{Index: 42, Leaf: []byte("leaf"), VRFProof: []byte("pi"), Duplicate: true}}
	srv := newTestServer(t, svc, []string{"correct-token"})

	resp := post(t, srv.URL, "correct-token", `{"label":"vlad@thelemail.com","record":"eyJ2IjoxfQ=="}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got response
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Index != 42 || !got.Duplicate || string(got.Leaf) != "leaf" || string(got.VRFProof) != "pi" {
		t.Fatalf("receipt = %+v", got)
	}
}

func TestSubmitRejectsAnInvalidSubmission(t *testing.T) {
	svc := &stubService{err: entity.Submission{}.Validate()}
	srv := newTestServer(t, svc, []string{"correct-token"})

	resp := post(t, srv.URL, "correct-token", `{"label":"","record":""}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestSubmitReportsAnUnavailableAppender(t *testing.T) {
	svc := &stubService{err: entity.ErrAppendUnavailable}
	srv := newTestServer(t, svc, []string{"correct-token"})

	resp := post(t, srv.URL, "correct-token", `{"label":"vlad@thelemail.com","record":"eyJ2IjoxfQ=="}`)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestSubmitRejectsEveryRequestWhenNoTokenIsConfigured(t *testing.T) {
	svc := &stubService{}
	srv := newTestServer(t, svc, nil)

	resp := post(t, srv.URL, "anything", `{"label":"vlad@thelemail.com","record":"eyJ2IjoxfQ=="}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}
