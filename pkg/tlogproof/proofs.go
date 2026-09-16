package tlogproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

var ErrCheckpointBehind = errors.New("tlogproof: checkpoint does not cover entry yet")

var ErrCheckpointStale = errors.New("tlogproof: checkpoint cosignatures are stale")

var ErrInvalidSignature = errors.New("tlogproof: checkpoint carries an invalid signature from a known key")

const (
	maxForwardSkew     = 5 * time.Minute
	maxCosignatureTime = 1<<53 - 1
)

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
	sigs, err := knownSignatures(signed, b.policy)
	if err != nil {
		return nil, torchwood.Checkpoint{}, err
	}
	checkpoint, _, err := torchwood.VerifyCheckpoint(signed, b.policy)
	if err != nil {
		return nil, torchwood.Checkpoint{}, fmt.Errorf("tlogproof: verify checkpoint: %w", err)
	}
	if err := b.checkFreshness(sigs, checkpoint.Origin); err != nil {
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
	type signer struct {
		name string
		hash uint32
	}
	var order []signer
	chosen := make(map[signer]note.Signature)
	newest := make(map[signer]int64)
	for _, sig := range sigs {
		key := signer{sig.Name, sig.Hash}
		if sig.Name == origin {
			if _, ok := chosen[key]; !ok {
				order = append(order, key)
				chosen[key] = sig
			}
			continue
		}
		ts, err := torchwood.CosignatureTimestamp(sig)
		if err != nil {
			return fmt.Errorf("tlogproof: cosignature %q timestamp: %w", sig.Name, err)
		}
		if ts > maxCosignatureTime {
			return fmt.Errorf("%w: cosignature %q timestamp out of range", ErrInvalidSignature, sig.Name)
		}
		signed := time.Unix(ts, 0)
		if now.Sub(signed) > b.maxCosigAge || signed.Sub(now) > maxForwardSkew {
			continue
		}
		if _, ok := chosen[key]; !ok {
			order = append(order, key)
		} else if ts <= newest[key] {
			continue
		}
		chosen[key] = sig
		newest[key] = ts
	}
	fresh := make([]note.Signature, 0, len(order))
	for _, key := range order {
		fresh = append(fresh, chosen[key])
	}
	if err := b.policy.Check(origin, fresh); err != nil {
		return fmt.Errorf("%w: %d of %d signatures inside freshness window: %w", ErrCheckpointStale, len(fresh), len(sigs), err)
	}
	return nil
}

func knownSignatures(signedNote []byte, known note.Verifiers) ([]note.Signature, error) {
	split := bytes.LastIndex(signedNote, []byte("\n\n"))
	if split < 0 {
		return nil, errors.New("tlogproof: checkpoint has no signature block")
	}
	text := signedNote[:split+1]
	var sigs []note.Signature
	for line := range strings.Lines(string(signedNote[split+2:])) {
		name, b64, ok := strings.Cut(strings.TrimPrefix(strings.TrimSuffix(line, "\n"), "— "), " ")
		raw, err := base64.StdEncoding.DecodeString(b64)
		if !ok || err != nil || len(raw) < 5 {
			return nil, errors.New("tlogproof: malformed checkpoint signature line")
		}
		hash := binary.BigEndian.Uint32(raw)
		verifier, err := known.Verifier(name, hash)
		var unknown *note.UnknownVerifierError
		if errors.As(err, &unknown) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("tlogproof: checkpoint signature %q: %w", name, err)
		}
		if !verifier.Verify(text, raw[4:]) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidSignature, name)
		}
		sigs = append(sigs, note.Signature{Name: name, Hash: hash, Base64: b64})
	}
	return sigs, nil
}

func LabelHash(label string) []byte {
	sum := sha256.Sum256([]byte(label))
	return sum[:]
}
