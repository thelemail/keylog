package tlogproof

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

var ErrCheckpointBehind = errors.New("tlogproof: checkpoint does not cover entry yet")

var ErrCheckpointStale = errors.New("tlogproof: checkpoint cosignatures are stale")

func LeafHash(beta, record []byte) []byte {
	h := sha256.New()
	h.Write(record)
	return h.Sum(beta)
}

type BuilderConfig struct {
	MaxCosignatureAge time.Duration
	Policy            torchwood.Policy
	Tiles             torchwood.TileReader
	Clock             func() time.Time
}

type Builder struct {
	maxCosigAge time.Duration
	policy      torchwood.Policy
	tiles       torchwood.TileReader
	clock       func() time.Time
}

func NewBuilder(cfg BuilderConfig) (*Builder, error) {
	if cfg.Policy == nil {
		return nil, errors.New("tlogproof: policy required")
	}
	if cfg.Tiles == nil {
		return nil, errors.New("tlogproof: tile reader required")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Builder{
		maxCosigAge: cfg.MaxCosignatureAge,
		policy:      cfg.Policy,
		tiles:       cfg.Tiles,
		clock:       clock,
	}, nil
}

func (b *Builder) Checkpoint(ctx context.Context) ([]byte, torchwood.Checkpoint, error) {
	signed, err := b.tiles.ReadEndpoint(ctx, "checkpoint")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, torchwood.Checkpoint{}, ErrCheckpointBehind
		}
		return nil, torchwood.Checkpoint{}, fmt.Errorf("tlogproof: read checkpoint: %w", err)
	}
	checkpoint, n, err := torchwood.VerifyCheckpoint(signed, b.policy)
	if err != nil {
		return nil, torchwood.Checkpoint{}, fmt.Errorf("tlogproof: verify checkpoint: %w", err)
	}
	if err := b.checkFreshness(n.Sigs, checkpoint.Origin); err != nil {
		return nil, torchwood.Checkpoint{}, err
	}
	return signed, checkpoint, nil
}

func (b *Builder) Build(ctx context.Context, index int64, leaf, extra []byte) ([]byte, error) {
	signed, checkpoint, err := b.Checkpoint(ctx)
	if err != nil {
		return nil, err
	}
	return b.BuildAt(ctx, signed, checkpoint, index, leaf, extra)
}

func (b *Builder) BuildAt(ctx context.Context, signed []byte, checkpoint torchwood.Checkpoint, index int64, leaf, extra []byte) ([]byte, error) {
	if index >= checkpoint.N {
		return nil, ErrCheckpointBehind
	}
	hashReader := torchwood.TileHashReaderWithContext(ctx, checkpoint.Tree, b.tiles)
	recordProof, err := tlog.ProveRecord(checkpoint.N, index, hashReader)
	if err != nil {
		return nil, fmt.Errorf("tlogproof: prove record %d: %w", index, err)
	}
	proof := torchwood.FormatProofWithExtraData(index, extra, recordProof, signed)
	if err := torchwood.VerifyProof(b.policy, tlog.RecordHash(leaf), proof); err != nil {
		return nil, fmt.Errorf("tlogproof: self-verify proof for entry %d: %w", index, err)
	}
	return proof, nil
}

func (b *Builder) checkFreshness(sigs []note.Signature, origin string) error {
	now := b.clock()
	for _, sig := range sigs {
		if sig.Name == origin {
			continue
		}
		ts, err := torchwood.CosignatureTimestamp(sig)
		if err != nil {
			return fmt.Errorf("tlogproof: cosignature %q timestamp: %w", sig.Name, err)
		}
		if now.Sub(time.Unix(ts, 0)) > b.maxCosigAge {
			return fmt.Errorf("%w: %q signed at %d", ErrCheckpointStale, sig.Name, ts)
		}
	}
	return nil
}

func LabelHash(label string) []byte {
	sum := sha256.Sum256([]byte(label))
	return sum[:]
}
