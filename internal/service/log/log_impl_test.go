package log

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"

	"github.com/thelemail/keylog/internal/config"
	"github.com/thelemail/keylog/internal/entity"
	"github.com/thelemail/keylog/internal/pkg/tlogstore"
	"github.com/thelemail/keylog/internal/repository"
	"github.com/thelemail/keylog/pkg/tlogproof"
	"github.com/thelemail/keylog/pkg/vrf"
)

type fakeEntries struct {
	rows []entity.Entry
}

func (f *fakeEntries) Claim(_ context.Context, e entity.Entry) (entity.Entry, bool, error) {
	for _, r := range f.rows {
		if bytes.Equal(r.Leaf, e.Leaf) {
			return r, true, nil
		}
	}
	f.rows = append(f.rows, e)
	return e, false, nil
}

func (f *fakeEntries) SetInclusion(_ context.Context, leaf []byte, index int64, includedAt time.Time) error {
	for i := range f.rows {
		if bytes.Equal(f.rows[i].Leaf, leaf) && f.rows[i].Index == nil {
			f.rows[i].Index = &index
			f.rows[i].IncludedAt = &includedAt
			return nil
		}
	}
	return nil
}

func (f *fakeEntries) GetByIndex(_ context.Context, index int64) (entity.Entry, error) {
	for _, r := range f.rows {
		if r.Index != nil && *r.Index == index {
			return r, nil
		}
	}
	return entity.Entry{}, repository.ErrEntryNotFound
}

func (f *fakeEntries) GetByLeaf(_ context.Context, leaf []byte) (entity.Entry, error) {
	for _, r := range f.rows {
		if bytes.Equal(r.Leaf, leaf) {
			return r, nil
		}
	}
	return entity.Entry{}, repository.ErrEntryNotFound
}

func (f *fakeEntries) ListPending(_ context.Context, limit int) ([]entity.Entry, error) {
	var out []entity.Entry
	for _, r := range f.rows {
		if r.Index == nil {
			out = append(out, r)
		}
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (f *fakeEntries) ListByLabelHash(_ context.Context, labelHash []byte) ([]entity.Entry, error) {
	var out []entity.Entry
	for _, r := range f.rows {
		if bytes.Equal(r.LabelHash, labelHash) && r.Index != nil {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeEntries) Count(context.Context) (int64, error) { return int64(len(f.rows)), nil }

func (f *fakeEntries) Import(_ context.Context, batch []entity.Entry) (int, error) {
	f.rows = append(f.rows, batch...)
	return len(batch), nil
}

func newTestService(t *testing.T) (*fakeEntries, *srv) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	dir, err := os.MkdirTemp("", "keylog-service")
	if err != nil {
		t.Fatal(err)
	}
	skey, vkey, err := note.GenerateKey(rand.Reader, "test.thelemail.com/keys")
	if err != nil {
		t.Fatal(err)
	}
	notePath := filepath.Join(dir, "note.key")
	if err := os.WriteFile(notePath, []byte(skey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	privB64, _ := vrf.GenerateKeyBase64()
	vrfPath := filepath.Join(dir, "vrf.key")
	if err := os.WriteFile(vrfPath, []byte(privB64+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Log{
		Path:               filepath.Join(dir, "log"),
		Origin:             "test.thelemail.com/keys",
		NoteKeyPath:        notePath,
		NoteVerifierKey:    vkey,
		VRFKeyPath:         vrfPath,
		CheckpointInterval: 100 * time.Millisecond,
		SweepBatch:         16,
	}
	log, err := tlogstore.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = log.Shutdown(context.Background())
		cancel()
		_ = os.RemoveAll(dir)
	})
	key, err := vrf.Load(vrfPath)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := tlogproof.NewPolicy(tlogstore.PolicyConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	tiles, err := torchwood.NewTileFS(os.DirFS(cfg.Path))
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := tlogproof.NewBuilder(tlogproof.BuilderConfig{
		MaxCosignatureAge: 24 * time.Hour,
		Policy:            policy,
		Tiles:             tiles,
	})
	if err != nil {
		t.Fatal(err)
	}
	repo := &fakeEntries{}
	return repo, New(repo, log, proofs, key, cfg, nil).(*srv)
}

func TestSubmitAppendsOnceAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	repo, svc := newTestService(t)

	in := entity.Submission{Label: "vlad@thelemail.com", Record: []byte(`{"v":1}`), Metadata: []byte("sig")}
	first, err := svc.Submit(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if first.Index != 0 {
		t.Fatalf("index = %d, want 0", first.Index)
	}
	if first.Duplicate {
		t.Fatal("first submission reported as duplicate")
	}
	if len(first.VRFProof) == 0 {
		t.Fatal("no VRF proof returned")
	}

	second, err := svc.Submit(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Duplicate {
		t.Fatal("repeat submission not reported as duplicate")
	}
	if second.Index != first.Index {
		t.Fatalf("repeat index = %d, want %d", second.Index, first.Index)
	}
	if len(repo.rows) != 1 {
		t.Fatalf("stored %d rows, want 1", len(repo.rows))
	}

	other, err := svc.Submit(ctx, entity.Submission{Label: "zoe@thelemail.com", Record: []byte(`{"v":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	if other.Index != 1 {
		t.Fatalf("second label index = %d, want 1", other.Index)
	}
}

func TestSubmitLeafMatchesTheDocumentedFormat(t *testing.T) {
	ctx := context.Background()
	repo, svc := newTestService(t)

	record := []byte(`{"v":1}`)
	receipt, err := svc.Submit(ctx, entity.Submission{Label: "vlad@thelemail.com", Record: record})
	if err != nil {
		t.Fatal(err)
	}
	beta, err := vrf.ProofHash(receipt.VRFProof)
	if err != nil {
		t.Fatal(err)
	}
	want := tlogproof.LeafHash(beta, record)
	if !bytes.Equal(receipt.Leaf, want) {
		t.Fatal("leaf is not vrf_r255(label) || sha256(record)")
	}
	if len(repo.rows[0].LabelHash) != 32 {
		t.Fatal("label hash is not sha256")
	}
	if bytes.Contains(repo.rows[0].LabelHash, []byte("vlad")) {
		t.Fatal("plaintext label leaked into the stored label hash")
	}
}

func TestSweepCompletesEntriesLeftPending(t *testing.T) {
	ctx := context.Background()
	repo, svc := newTestService(t)

	pi, beta := svc.vrfKey.Prove([]byte("vlad@thelemail.com"))
	record := []byte(`{"v":7}`)
	repo.rows = append(repo.rows, entity.Entry{
		LabelHash:   tlogproof.LabelHash("vlad@thelemail.com"),
		Leaf:        tlogproof.LeafHash(beta, record),
		Record:      record,
		VRFProof:    pi,
		SubmittedAt: time.Now().UTC(),
	})

	n, err := svc.SweepPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("swept %d entries, want 1", n)
	}
	if repo.rows[0].Index == nil {
		t.Fatal("swept entry has no index")
	}

	again, err := svc.SweepPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again != 0 {
		t.Fatalf("second sweep appended %d entries, want 0", again)
	}
}

func TestSubmitRejectsEmptyRecord(t *testing.T) {
	_, svc := newTestService(t)
	if _, err := svc.Submit(context.Background(), entity.Submission{Label: "vlad@thelemail.com"}); err == nil {
		t.Fatal("empty record accepted")
	}
}

func TestHistoryIsScopedToTheLabel(t *testing.T) {
	ctx := context.Background()
	_, svc := newTestService(t)

	for _, r := range []string{`{"v":1}`, `{"v":2}`} {
		if _, err := svc.Submit(ctx, entity.Submission{Label: "vlad@thelemail.com", Record: []byte(r)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.Submit(ctx, entity.Submission{Label: "zoe@thelemail.com", Record: []byte(`{"v":1}`)}); err != nil {
		t.Fatal(err)
	}

	history, err := svc.History(ctx, "vlad@thelemail.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(history.Entries) != 2 {
		t.Fatalf("history has %d entries, want 2", len(history.Entries))
	}

	if _, err := svc.History(ctx, "nobody@thelemail.com"); !errors.Is(err, entity.ErrEntryNotFound) {
		t.Fatalf("history for an unknown label returned %v, want ErrEntryNotFound", err)
	}
}

func TestProofCoversASubmittedEntry(t *testing.T) {
	ctx := context.Background()
	_, svc := newTestService(t)

	receipt, err := svc.Submit(ctx, entity.Submission{Label: "vlad@thelemail.com", Record: []byte(`{"v":1}`)})
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(20 * time.Second)
	var proof []byte
	for {
		proof, err = svc.Proof(ctx, receipt.Index)
		if err == nil {
			break
		}
		if !errors.Is(err, tlogproof.ErrCheckpointBehind) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("checkpoint never covered the submitted entry")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !bytes.HasPrefix(proof, []byte("c2sp.org/tlog-proof@v1")) {
		t.Fatalf("proof does not carry the tlog-proof header: %q", proof[:min(40, len(proof))])
	}

	if _, err := svc.Proof(ctx, 999); !errors.Is(err, repository.ErrEntryNotFound) {
		t.Fatalf("proof for an unknown index returned %v, want ErrEntryNotFound", err)
	}
}
