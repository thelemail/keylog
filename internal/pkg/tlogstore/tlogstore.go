package tlogstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"

	"github.com/thelemail/keylog/internal/config"
	"github.com/thelemail/keylog/pkg/tlogproof"
)

type Log struct {
	Appender *tessera.Appender
	Reader   tessera.LogReader
	shutdown func(context.Context) error
}

func New(ctx context.Context, cfg config.Log) (*Log, error) {
	if cfg.Path == "" {
		return nil, errors.New("tlogstore: path required")
	}
	if err := os.MkdirAll(cfg.Path, 0o750); err != nil {
		return nil, fmt.Errorf("tlogstore: create log dir: %w", err)
	}
	signer, err := loadSigner(cfg)
	if err != nil {
		return nil, err
	}
	driver, err := posix.New(ctx, posix.Config{Path: cfg.Path})
	if err != nil {
		return nil, fmt.Errorf("tlogstore: posix driver: %w", err)
	}
	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithBatching(1, tessera.DefaultBatchMaxAge).
		WithCheckpointInterval(cfg.CheckpointInterval).
		WithAntispam(1024, nil)
	if cfg.WitnessPolicyPath != "" {
		policy, err := os.ReadFile(cfg.WitnessPolicyPath)
		if err != nil {
			return nil, fmt.Errorf("tlogstore: read witness policy %s: %w", cfg.WitnessPolicyPath, err)
		}
		group, err := tessera.NewWitnessGroupFromPolicy(policy)
		if err != nil {
			return nil, fmt.Errorf("tlogstore: parse witness policy: %w", err)
		}
		opts = opts.WithWitnesses(group, nil)
	}
	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		return nil, fmt.Errorf("tlogstore: appender: %w", err)
	}
	return &Log{Appender: appender, Reader: reader, shutdown: shutdown}, nil
}

func (l *Log) Append(ctx context.Context, leaf []byte) (index uint64, isDup bool, err error) {
	idx, err := l.Appender.Add(ctx, tessera.NewEntry(leaf))()
	if err != nil {
		return 0, false, fmt.Errorf("tlogstore: append: %w", err)
	}
	return idx.Index, idx.IsDup, nil
}

func (l *Log) Shutdown(ctx context.Context) error {
	if l.shutdown == nil {
		return nil
	}
	return l.shutdown(ctx)
}

func loadSigner(cfg config.Log) (note.Signer, error) {
	if cfg.NoteKeyPath == "" {
		return nil, errors.New("tlogstore: note key path required")
	}
	raw, err := os.ReadFile(cfg.NoteKeyPath)
	if err != nil {
		return nil, fmt.Errorf("tlogstore: read note key %s: %w", cfg.NoteKeyPath, err)
	}
	signer, err := note.NewSigner(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("tlogstore: parse note key: %w", err)
	}
	return signer, nil
}

func PolicyConfig(cfg config.Log) tlogproof.PolicyConfig {
	return tlogproof.PolicyConfig{
		Origin:            cfg.Origin,
		NoteVerifierKey:   cfg.NoteVerifierKey,
		NoteKeyPath:       cfg.NoteKeyPath,
		WitnessPolicyPath: cfg.WitnessPolicyPath,
	}
}
