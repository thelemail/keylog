package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sync/errgroup"
)

var ErrShutdownTimeout = errors.New("shutdown timeout exceeded; some services did not drain")

func Run(ctx context.Context, shutdownTimeout time.Duration, services ...Service) error {
	if len(services) == 0 {
		return errors.New("no services to run")
	}

	serviceCtx, stopServices := context.WithCancel(context.WithoutCancel(ctx))
	defer stopServices()

	g, gctx := errgroup.WithContext(serviceCtx)
	for _, svc := range services {
		g.Go(func() error {
			slog.InfoContext(gctx, "service starting", "service", svc.Name())
			err := svc.Run(gctx)
			slog.InfoContext(gctx, "service stopped", "service", svc.Name())
			if err != nil && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("%s: %w", svc.Name(), err)
			}
			return nil
		})
	}

	done := make(chan error, 1)
	go func() { done <- g.Wait() }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}

	slog.InfoContext(ctx, "draining services", "timeout", shutdownTimeout)
	stopServices()

	select {
	case err := <-done:
		return err
	case <-time.After(shutdownTimeout):
		return ErrShutdownTimeout
	}
}
