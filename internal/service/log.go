package service

import (
	"context"

	"github.com/thelemail/keylog/internal/entity"
)

type Log interface {
	Submit(ctx context.Context, in entity.Submission) (entity.Receipt, error)
	SweepPending(ctx context.Context) (int, error)
	Proof(ctx context.Context, index int64) ([]byte, error)
	History(ctx context.Context, label string) (entity.History, error)
}
