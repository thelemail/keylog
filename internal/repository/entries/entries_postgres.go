package entries

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/thelemail/keylog/internal/entity"
	"github.com/thelemail/keylog/internal/pkg/postgres"
	"github.com/thelemail/keylog/internal/repository"
)

const columns = `label_hash, leaf, record, metadata, vrf_proof, log_index, submitted_at, included_at`

type repo struct {
	db *postgres.Client
}

func New(db *postgres.Client) repository.Entries {
	return &repo{db: db}
}

func (r *repo) Claim(ctx context.Context, e entity.Entry) (entity.Entry, bool, error) {
	const q = `
INSERT INTO entries (label_hash, leaf, record, metadata, vrf_proof, submitted_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (leaf) DO NOTHING`
	res, err := r.db.Querier(ctx).ExecContext(ctx, q, e.LabelHash, e.Leaf, e.Record, e.Metadata, e.VRFProof, e.SubmittedAt)
	if err != nil {
		return entity.Entry{}, false, fmt.Errorf("entries claim: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return entity.Entry{}, false, fmt.Errorf("entries claim: %w", err)
	}
	stored, err := r.GetByLeaf(ctx, e.Leaf)
	if err != nil {
		return entity.Entry{}, false, err
	}
	return stored, affected == 0, nil
}

func (r *repo) SetInclusion(ctx context.Context, leaf []byte, index int64, includedAt time.Time) error {
	const q = `
UPDATE entries
SET log_index = $2, included_at = $3
WHERE leaf = $1 AND log_index IS NULL`
	if _, err := r.db.Querier(ctx).ExecContext(ctx, q, leaf, index, includedAt); err != nil {
		return fmt.Errorf("entries set inclusion: %w", err)
	}
	return nil
}

func (r *repo) GetByLeaf(ctx context.Context, leaf []byte) (entity.Entry, error) {
	q := `SELECT ` + columns + ` FROM entries WHERE leaf = $1`
	e, err := scan(r.db.Querier(ctx).QueryRowContext(ctx, q, leaf))
	if errors.Is(err, sql.ErrNoRows) {
		return entity.Entry{}, repository.ErrEntryNotFound
	}
	if err != nil {
		return entity.Entry{}, fmt.Errorf("entries get by leaf: %w", err)
	}
	return e, nil
}

func (r *repo) GetByIndex(ctx context.Context, index int64) (entity.Entry, error) {
	q := `SELECT ` + columns + ` FROM entries WHERE log_index = $1`
	e, err := scan(r.db.Querier(ctx).QueryRowContext(ctx, q, index))
	if errors.Is(err, sql.ErrNoRows) {
		return entity.Entry{}, repository.ErrEntryNotFound
	}
	if err != nil {
		return entity.Entry{}, fmt.Errorf("entries get by index: %w", err)
	}
	return e, nil
}

func (r *repo) ListPending(ctx context.Context, limit int) ([]entity.Entry, error) {
	q := `SELECT ` + columns + ` FROM entries WHERE log_index IS NULL ORDER BY id LIMIT $1`
	return r.query(ctx, "entries list pending", q, limit)
}

func (r *repo) ListByLabelHash(ctx context.Context, labelHash []byte) ([]entity.Entry, error) {
	q := `SELECT ` + columns + ` FROM entries WHERE label_hash = $1 AND log_index IS NOT NULL ORDER BY log_index`
	return r.query(ctx, "entries list by label", q, labelHash)
}

func (r *repo) Count(ctx context.Context) (int64, error) {
	var n int64
	if err := r.db.Querier(ctx).QueryRowContext(ctx, `SELECT count(*) FROM entries`).Scan(&n); err != nil {
		return 0, fmt.Errorf("entries count: %w", err)
	}
	return n, nil
}

func (r *repo) Import(ctx context.Context, batch []entity.Entry) (int, error) {
	const q = `
INSERT INTO entries (label_hash, leaf, record, metadata, vrf_proof, log_index, submitted_at, included_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (leaf) DO NOTHING`
	imported := 0
	err := r.db.WithTx(ctx, func(ctx context.Context) error {
		for _, e := range batch {
			res, err := r.db.Querier(ctx).ExecContext(ctx, q,
				e.LabelHash, e.Leaf, e.Record, e.Metadata, e.VRFProof, e.Index, e.SubmittedAt, e.IncludedAt)
			if err != nil {
				return fmt.Errorf("entries import leaf %x: %w", e.Leaf, err)
			}
			affected, err := res.RowsAffected()
			if err != nil {
				return fmt.Errorf("entries import: %w", err)
			}
			imported += int(affected)
		}
		return nil
	})
	return imported, err
}

func (r *repo) query(ctx context.Context, op, q string, args ...any) ([]entity.Entry, error) {
	rows, err := r.db.Querier(ctx).QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()
	var out []entity.Entry
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return out, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scan(s scanner) (entity.Entry, error) {
	var e entity.Entry
	var metadata, vrfProof []byte
	var index sql.NullInt64
	var includedAt sql.NullTime
	if err := s.Scan(&e.LabelHash, &e.Leaf, &e.Record, &metadata, &vrfProof, &index, &e.SubmittedAt, &includedAt); err != nil {
		return entity.Entry{}, err
	}
	e.Metadata = metadata
	e.VRFProof = vrfProof
	if index.Valid {
		e.Index = &index.Int64
	}
	if includedAt.Valid {
		t := includedAt.Time.UTC()
		e.IncludedAt = &t
	}
	e.SubmittedAt = e.SubmittedAt.UTC()
	return e, nil
}
