package tlogstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/torchwood"
	"github.com/transparency-dev/tessera"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/thelemail/keylog/internal/config"
	"github.com/thelemail/keylog/pkg/tlogproof"
)

const testOrigin = "test.thelemail.com/keys"

func testConfig(t *testing.T) config.Log {
	t.Helper()
	dir := t.TempDir()
	skey, vkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "note.key")
	if err := os.WriteFile(keyPath, []byte(skey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Log{
		Path:               filepath.Join(dir, "log"),
		Origin:             testOrigin,
		NoteKeyPath:        keyPath,
		NoteVerifierKey:    vkey,
		CheckpointInterval: 100 * time.Millisecond,
		MaxCosignatureAge:  24 * time.Hour,
	}
}

func TestAppendAndVerifyCheckpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := testConfig(t)
	log, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := log.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	}()

	leaf := make([]byte, 96)
	sum := sha256.Sum256([]byte("record"))
	copy(leaf[64:], sum[:])
	idx, err := log.Appender.Add(ctx, tessera.NewEntry(leaf))()
	if err != nil {
		t.Fatal(err)
	}
	if idx.Index != 0 {
		t.Fatalf("index = %d, want 0", idx.Index)
	}

	dup, err := log.Appender.Add(ctx, tessera.NewEntry(leaf))()
	if err != nil {
		t.Fatal(err)
	}
	if !dup.IsDup || dup.Index != idx.Index {
		t.Fatalf("dup = %+v, want IsDup at index %d", dup, idx.Index)
	}

	policy, err := tlogproof.NewPolicy(PolicyConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(20 * time.Second)
	var checkpoint torchwood.Checkpoint
	for {
		raw, err := os.ReadFile(filepath.Join(cfg.Path, "checkpoint"))
		if err == nil {
			cp, _, err := torchwood.VerifyCheckpoint(raw, policy)
			if err != nil {
				t.Fatalf("verify checkpoint: %v", err)
			}
			if cp.N > int64(idx.Index) {
				checkpoint = cp
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("checkpoint never covered the appended entry")
		}
		time.Sleep(50 * time.Millisecond)
	}

	tileFS, err := torchwood.NewTileFS(os.DirFS(cfg.Path))
	if err != nil {
		t.Fatal(err)
	}
	hashReader := torchwood.TileHashReaderWithContext(ctx, checkpoint.Tree, tileFS)
	proof, err := tlog.ProveRecord(checkpoint.N, int64(idx.Index), hashReader)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlog.CheckRecord(proof, checkpoint.N, checkpoint.Hash, int64(idx.Index), tlog.RecordHash(leaf)); err != nil {
		t.Fatalf("inclusion proof: %v", err)
	}

	builder, err := tlogproof.NewBuilder(tlogproof.BuilderConfig{
		MaxCosignatureAge: cfg.MaxCosignatureAge,
		Policy:            policy,
		Tiles:             tileFS,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := builder.Build(ctx, int64(idx.Index), leaf, []byte("extra"))
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	if err := torchwood.VerifyProof(policy, tlog.RecordHash(leaf), bundle); err != nil {
		t.Fatalf("verify built proof: %v", err)
	}
	if _, err := builder.Build(ctx, checkpoint.N, leaf, nil); err == nil {
		t.Fatal("built a proof for an index the checkpoint does not cover")
	}
}
