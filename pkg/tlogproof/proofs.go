package tlogproof

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"filippo.io/torchwood"
	"github.com/thelemail/trust/tlog"
	sumdb "golang.org/x/mod/sumdb/tlog"
)

var ErrCheckpointBehind = errors.New("tlogproof: checkpoint does not cover entry yet")

type BuilderConfig struct {
	Policy tlog.Policy
	Tiles  torchwood.TileReader
	Clock  func() time.Time
}

type Builder struct {
	policy tlog.Policy
	tiles  torchwood.TileReader
	clock  func() time.Time
}

func NewBuilder(cfg BuilderConfig) (*Builder, error) {
	if cfg.Policy.LogVerifierKey == "" {
		return nil, errors.New("tlogproof: policy required")
	}
	if cfg.Tiles == nil {
		return nil, errors.New("tlogproof: tile reader required")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Builder{policy: cfg.Policy, tiles: cfg.Tiles, clock: clock}, nil
}

func (b *Builder) Checkpoint(ctx context.Context) ([]byte, torchwood.Checkpoint, error) {
	signed, err := b.tiles.ReadEndpoint(ctx, "checkpoint")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, torchwood.Checkpoint{}, ErrCheckpointBehind
		}
		return nil, torchwood.Checkpoint{}, fmt.Errorf("tlogproof: read checkpoint: %w", err)
	}
	checkpoint, err := tlog.VerifyCheckpoint(signed, b.policy, b.clock())
	if err != nil {
		return nil, torchwood.Checkpoint{}, fmt.Errorf("tlogproof: verify checkpoint: %w", err)
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
	recordProof, err := sumdb.ProveRecord(checkpoint.N, index, hashReader)
	if err != nil {
		return nil, fmt.Errorf("tlogproof: prove record %d: %w", index, err)
	}
	proof := torchwood.FormatProofWithExtraData(index, extra, recordProof, signed)
	if _, err := tlog.VerifyInclusion(proof, leaf, b.policy, b.clock()); err != nil {
		return nil, fmt.Errorf("tlogproof: self-verify proof for entry %d: %w", index, err)
	}
	return proof, nil
}
