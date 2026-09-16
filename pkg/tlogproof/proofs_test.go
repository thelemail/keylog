package tlogproof_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/thelemail/keylog/pkg/tlogproof"
)

const testOrigin = "test.thelemail.com/keys"

type fixedTimeCosigner struct {
	name string
	hash uint32
	key  ed25519.PrivateKey
	ts   time.Time
}

func (s *fixedTimeCosigner) Name() string    { return s.name }
func (s *fixedTimeCosigner) KeyHash() uint32 { return s.hash }

func (s *fixedTimeCosigner) Sign(msg []byte) ([]byte, error) {
	m := fmt.Appendf(nil, "cosignature/v1\ntime %d\n%s", s.ts.Unix(), msg)
	out := binary.BigEndian.AppendUint64(nil, uint64(s.ts.Unix()))
	return append(out, ed25519.Sign(s.key, m)...), nil
}

type witness struct {
	name string
	key  ed25519.PrivateKey
	hash uint32
	vkey string
}

func (w witness) at(ts time.Time) note.Signer {
	return &fixedTimeCosigner{name: w.name, hash: w.hash, key: w.key, ts: ts}
}

type corruptSigner struct {
	note.Signer
}

func (s corruptSigner) Sign(msg []byte) ([]byte, error) {
	sig, err := s.Signer.Sign(msg)
	if err != nil {
		return nil, err
	}
	sig[len(sig)-1] ^= 0x01
	return sig, nil
}

type quorum struct {
	logSigner note.Signer
	witnesses []witness
	policy    torchwood.Policy
	text      string
}

func newQuorum(t *testing.T) quorum {
	t.Helper()
	logSkey, logVkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	logSigner, err := note.NewSigner(logSkey)
	if err != nil {
		t.Fatal(err)
	}
	var witnesses []witness
	policyLines := []string{"log " + logVkey}
	for i := range 3 {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("witness%d.example.org", i+1)
		reference, err := torchwood.NewCosignatureSigner(name, priv)
		if err != nil {
			t.Fatal(err)
		}
		w := witness{name: name, key: priv, hash: reference.KeyHash(), vkey: reference.Verifier().String()}
		witnesses = append(witnesses, w)
		policyLines = append(policyLines, fmt.Sprintf("witness w%d %s", i+1, w.vkey))
	}
	policyLines = append(policyLines, "group trusted 2 w1 w2 w3", "quorum trusted")
	policy, err := torchwood.ParsePolicy([]byte(strings.Join(policyLines, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	text := torchwood.Checkpoint{Origin: testOrigin, Tree: tlog.Tree{N: 1, Hash: tlog.RecordHash([]byte("entry"))}}.String()
	return quorum{logSigner: logSigner, witnesses: witnesses, policy: policy, text: text}
}

func (q quorum) checkpoint(t *testing.T, now time.Time, maxAge time.Duration, signers ...note.Signer) (torchwood.Checkpoint, error) {
	t.Helper()
	signed, err := note.Sign(&note.Note{Text: q.text}, signers...)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), signed, 0o600); err != nil {
		t.Fatal(err)
	}
	tiles, err := torchwood.NewTileFS(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	builder, err := tlogproof.NewBuilder(tlogproof.BuilderConfig{
		MaxCosignatureAge: maxAge,
		Policy:            q.policy,
		Tiles:             tiles,
		Clock:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, checkpoint, err := builder.Checkpoint(t.Context())
	return checkpoint, err
}

func TestCheckpointFreshnessAppliesToQuorum(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	maxAge := 24 * time.Hour
	q := newQuorum(t)
	fresh := now.Add(-time.Minute)
	stale := now.Add(-72 * time.Hour)
	future := now.Add(time.Hour)
	w1, w2, w3 := q.witnesses[0], q.witnesses[1], q.witnesses[2]

	tests := []struct {
		name    string
		signers []note.Signer
		stale   bool
	}{
		{"fresh quorum", []note.Signer{w1.at(fresh), w2.at(fresh)}, false},
		{"fresh quorum with stale extra", []note.Signer{w1.at(fresh), w2.at(fresh), w3.at(stale)}, false},
		{"fresh quorum with future extra", []note.Signer{w1.at(fresh), w2.at(fresh), w3.at(future)}, false},
		{"exactly max age", []note.Signer{w1.at(now.Add(-maxAge)), w2.at(fresh)}, false},
		{"exactly forward skew", []note.Signer{w1.at(now.Add(5 * time.Minute)), w2.at(fresh)}, false},
		{"one fresh two stale", []note.Signer{w1.at(fresh), w2.at(stale), w3.at(stale)}, true},
		{"all future", []note.Signer{w1.at(future), w2.at(future)}, true},
		{"one fresh one stale one future", []note.Signer{w1.at(fresh), w2.at(stale), w3.at(future)}, true},
		{"one second past max age", []note.Signer{w1.at(now.Add(-maxAge - time.Second)), w2.at(fresh)}, true},
		{"one second beyond forward skew", []note.Signer{w1.at(now.Add(5*time.Minute + time.Second)), w2.at(fresh)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkpoint, err := q.checkpoint(t, now, maxAge, append([]note.Signer{q.logSigner}, tt.signers...)...)
			if tt.stale {
				if !errors.Is(err, tlogproof.ErrCheckpointStale) {
					t.Fatalf("err = %v, want ErrCheckpointStale", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkpoint: %v", err)
			}
			if checkpoint.N != 1 {
				t.Fatalf("tree size = %d, want 1", checkpoint.N)
			}
		})
	}
}

var errQuorumUnmet = errors.New("quorum unmet")

func TestCheckpointSignatureOrdering(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	maxAge := 24 * time.Hour
	q := newQuorum(t)
	fresh := now.Add(-time.Minute)
	fresher := now.Add(-30 * time.Second)
	stale := now.Add(-72 * time.Hour)
	future := now.Add(time.Hour)
	w1, w2, w3 := q.witnesses[0], q.witnesses[1], q.witnesses[2]
	log, badLog := q.logSigner, corruptSigner{q.logSigner}
	bad := corruptSigner{w1.at(fresh)}

	tests := []struct {
		name    string
		signers []note.Signer
		want    error
	}{
		{"invalid witness first", []note.Signer{log, bad, w1.at(fresh), w2.at(fresh)}, tlogproof.ErrInvalidSignature},
		{"invalid witness last", []note.Signer{log, w1.at(fresh), w2.at(fresh), bad}, tlogproof.ErrInvalidSignature},
		{"invalid extra witness", []note.Signer{log, w1.at(fresh), w2.at(fresh), corruptSigner{w3.at(fresh)}}, tlogproof.ErrInvalidSignature},
		{"invalid log first", []note.Signer{badLog, log, w1.at(fresh), w2.at(fresh)}, tlogproof.ErrInvalidSignature},
		{"invalid log last", []note.Signer{log, w1.at(fresh), w2.at(fresh), badLog}, tlogproof.ErrInvalidSignature},
		{"repeated log", []note.Signer{log, log, w1.at(fresh), w2.at(fresh)}, nil},
		{"fresh then fresher", []note.Signer{log, w1.at(fresh), w1.at(fresher), w2.at(fresh)}, nil},
		{"fresher then fresh", []note.Signer{log, w1.at(fresher), w1.at(fresh), w2.at(fresh)}, nil},
		{"stale then fresh", []note.Signer{log, w1.at(stale), w1.at(fresh), w2.at(fresh)}, nil},
		{"fresh then stale", []note.Signer{log, w1.at(fresh), w1.at(stale), w2.at(fresh)}, nil},
		{"future then fresh", []note.Signer{log, w1.at(future), w1.at(fresh), w2.at(fresh)}, nil},
		{"fresh then future", []note.Signer{log, w1.at(fresh), w1.at(future), w2.at(fresh)}, nil},
		{"one witness twice", []note.Signer{log, w1.at(fresh), w1.at(fresher)}, errQuorumUnmet},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := q.checkpoint(t, now, maxAge, tt.signers...)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("checkpoint: %v", err)
				}
				return
			}
			if tt.want == errQuorumUnmet {
				if err == nil || errors.Is(err, tlogproof.ErrInvalidSignature) {
					t.Fatalf("err = %v, want an unmet quorum", err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}
