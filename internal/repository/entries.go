package repository

import (
	"context"
	"errors"
	"time"

	"github.com/thelemail/keylog/internal/entity"
)

var ErrEntryNotFound = errors.New("repository: entry not found")

type Entries interface {
	Claim(ctx context.Context, e entity.Entry) (entity.Entry, bool, error)
	SetInclusion(ctx context.Context, leaf []byte, index int64, includedAt time.Time) error
	GetByLeaf(ctx context.Context, leaf []byte) (entity.Entry, error)
	GetByIndex(ctx context.Context, index int64) (entity.Entry, error)
	ListPending(ctx context.Context, limit int) ([]entity.Entry, error)
	ListByLabelHash(ctx context.Context, labelHash []byte) ([]entity.Entry, error)
	Count(ctx context.Context) (int64, error)
	Import(ctx context.Context, entries []entity.Entry) (int, error)
}
