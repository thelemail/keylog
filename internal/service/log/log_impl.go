package log

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/thelemail/keylog/internal/config"
	"github.com/thelemail/keylog/internal/entity"
	"github.com/thelemail/keylog/internal/pkg/tlogstore"
	"github.com/thelemail/keylog/internal/repository"
	"github.com/thelemail/keylog/internal/service"
	"github.com/thelemail/keylog/pkg/tlogproof"
	"github.com/thelemail/keylog/pkg/vrf"
)

type srv struct {
	entries  repository.Entries
	log      *tlogstore.Log
	proofs   *tlogproof.Builder
	vrfKey   *vrf.Key
	batch    int
	clock    func() time.Time
	appendMu sync.Mutex
}

func New(entries repository.Entries, log *tlogstore.Log, proofs *tlogproof.Builder, vrfKey *vrf.Key, cfg config.Log, clock func() time.Time) service.Log {
	if clock == nil {
		clock = time.Now
	}
	batch := cfg.SweepBatch
	if batch <= 0 {
		batch = 64
	}
	return &srv{
		entries: entries,
		log:     log,
		proofs:  proofs,
		vrfKey:  vrfKey,
		batch:   batch,
		clock:   clock,
	}
}

func (s *srv) Submit(ctx context.Context, in entity.Submission) (entity.Receipt, error) {
	if err := in.Validate(); err != nil {
		return entity.Receipt{}, err
	}
	if s.log == nil || s.vrfKey == nil {
		return entity.Receipt{}, entity.ErrAppendUnavailable
	}
	pi, beta := s.vrfKey.Prove([]byte(in.Label))
	leaf := tlogproof.LeafHash(beta, in.Record)
	labelHash := tlogproof.LabelHash(in.Label)

	stored, duplicate, err := s.entries.Claim(ctx, entity.Entry{
		LabelHash:   labelHash,
		Leaf:        leaf,
		Record:      in.Record,
		Metadata:    in.Metadata,
		VRFProof:    pi,
		SubmittedAt: s.clock().UTC(),
	})
	if err != nil {
		return entity.Receipt{}, fmt.Errorf("submit: %w", err)
	}
	if stored.Index != nil {
		return entity.Receipt{Index: *stored.Index, Leaf: leaf, VRFProof: stored.VRFProof, Duplicate: duplicate}, nil
	}

	index, err := s.append(ctx, stored)
	if err != nil {
		return entity.Receipt{}, err
	}
	return entity.Receipt{Index: index, Leaf: leaf, VRFProof: stored.VRFProof, Duplicate: duplicate}, nil
}

func (s *srv) SweepPending(ctx context.Context) (int, error) {
	if s.log == nil || s.vrfKey == nil {
		return 0, entity.ErrAppendUnavailable
	}
	pending, err := s.entries.ListPending(ctx, s.batch)
	if err != nil {
		return 0, fmt.Errorf("sweep: %w", err)
	}
	appended := 0
	for _, e := range pending {
		if _, err := s.append(ctx, e); err != nil {
			return appended, err
		}
		appended++
	}
	return appended, nil
}

func (s *srv) Proof(ctx context.Context, index int64) ([]byte, error) {
	if s.proofs == nil {
		return nil, entity.ErrProofsUnavailable
	}
	entry, err := s.entries.GetByIndex(ctx, index)
	if err != nil {
		return nil, fmt.Errorf("proof: %w", err)
	}
	proof, err := s.proofs.Build(ctx, index, entry.Leaf, entry.VRFProof)
	if err != nil {
		return nil, fmt.Errorf("proof: %w", err)
	}
	return proof, nil
}

func (s *srv) History(ctx context.Context, label string) (entity.History, error) {
	entries, err := s.entries.ListByLabelHash(ctx, tlogproof.LabelHash(label))
	if err != nil {
		return entity.History{}, fmt.Errorf("history: %w", err)
	}
	if len(entries) == 0 {
		return entity.History{}, entity.ErrEntryNotFound
	}
	return entity.History{
		Label:    label,
		VRFProof: entries[len(entries)-1].VRFProof,
		Entries:  entries,
	}, nil
}

func (s *srv) append(ctx context.Context, e entity.Entry) (int64, error) {
	s.appendMu.Lock()
	defer s.appendMu.Unlock()

	current, err := s.entries.GetByLeaf(ctx, e.Leaf)
	if err != nil {
		return 0, fmt.Errorf("reload leaf %x: %w", e.Leaf, err)
	}
	if current.Index != nil {
		return *current.Index, nil
	}

	index, _, err := s.log.Append(ctx, e.Leaf)
	if err != nil {
		return 0, fmt.Errorf("append leaf %x: %w", e.Leaf, err)
	}
	if err := s.entries.SetInclusion(ctx, e.Leaf, int64(index), s.clock().UTC()); err != nil {
		return 0, fmt.Errorf("record inclusion for leaf %x: %w", e.Leaf, err)
	}
	return int64(index), nil
}
