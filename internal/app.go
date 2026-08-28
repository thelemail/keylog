package internal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"filippo.io/torchwood"
	"github.com/go-chi/chi/v5"

	"github.com/thelemail/keylog/internal/config"
	loghandler "github.com/thelemail/keylog/internal/handler/http/log"
	"github.com/thelemail/keylog/internal/handler/http/middleware"
	submithandler "github.com/thelemail/keylog/internal/handler/http/submit"
	"github.com/thelemail/keylog/internal/pkg/postgres"
	"github.com/thelemail/keylog/internal/pkg/tlogstore"
	"github.com/thelemail/keylog/internal/repository"
	"github.com/thelemail/keylog/internal/repository/entries"
	"github.com/thelemail/keylog/internal/service"
	logsvc "github.com/thelemail/keylog/internal/service/log"
	"github.com/thelemail/keylog/pkg/tlogproof"
	"github.com/thelemail/keylog/pkg/vrf"
)

type App struct {
	Config  config.Config
	DB      *postgres.Client
	Entries repository.Entries
	Log     *tlogstore.Log
	Proofs  *tlogproof.Builder
	VRFKey  *vrf.Key
	Service service.Log
}

func NewApp(ctx context.Context, cfg config.Config, withAppender bool) (*App, func(), error) {
	db, err := postgres.New(ctx, cfg.Postgres)
	if err != nil {
		return nil, nil, fmt.Errorf("postgres: %w", err)
	}
	cleanup := func() { _ = db.Close() }

	app := &App{
		Config:  cfg,
		DB:      db,
		Entries: entries.New(db),
	}
	proofs, err := newProofBuilder(cfg.Log)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	app.Proofs = proofs

	if !withAppender {
		app.Service = logsvc.New(app.Entries, nil, proofs, nil, cfg.Log, time.Now)
		return app, cleanup, nil
	}

	key, err := vrf.Load(cfg.Log.VRFKeyPath)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	log, err := tlogstore.New(ctx, cfg.Log)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	logCleanup := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
		defer cancel()
		_ = log.Shutdown(shutdownCtx)
		_ = db.Close()
	}

	app.Log = log
	app.VRFKey = key
	app.Service = logsvc.New(app.Entries, log, proofs, key, cfg.Log, time.Now)
	return app, logCleanup, nil
}

func newProofBuilder(cfg config.Log) (*tlogproof.Builder, error) {
	policy, err := tlogproof.NewPolicy(tlogstore.PolicyConfig(cfg))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.Path, 0o750); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	tiles, err := torchwood.NewTileFS(os.DirFS(cfg.Path))
	if err != nil {
		return nil, fmt.Errorf("tile fs: %w", err)
	}
	return tlogproof.NewBuilder(tlogproof.BuilderConfig{
		MaxCosignatureAge: cfg.MaxCosignatureAge,
		Policy:            policy,
		Tiles:             tiles,
	})
}

type Server struct {
	srv           *http.Server
	svc           service.Log
	sweepInterval time.Duration
	shutdown      time.Duration
}

func NewServer(app *App) *Server {
	cfg := app.Config
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RecoverPanic)
	r.Use(middleware.AccessLog)

	r.Get("/healthz", ok)
	r.Get("/readyz", ok)

	if cfg.HTTP.WellKnownPath != "" {
		r.Handle("/.well-known/*", http.StripPrefix("/.well-known/", http.FileServer(http.Dir(cfg.HTTP.WellKnownPath))))
	}

	loghandler.New(app.Service, cfg.Log.Path).Mount(r)
	submithandler.New(app.Service, cfg.Submit.Tokens, cfg.Submit.MaxBodyBytes).Mount(r)

	interval := cfg.Log.SweepInterval
	if interval <= 0 {
		interval = time.Second
	}
	return &Server{
		srv: &http.Server{
			Addr:         cfg.HTTP.Addr,
			Handler:      r,
			ReadTimeout:  cfg.HTTP.ReadTimeout,
			WriteTimeout: cfg.HTTP.WriteTimeout,
		},
		svc:           app.Service,
		sweepInterval: interval,
		shutdown:      cfg.HTTP.ShutdownTimeout,
	}
}

func (s *Server) Name() string { return "keylog" }

func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()
	go s.sweepLoop(ctx)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdown)
		defer cancel()
		return s.srv.Shutdown(shutdownCtx)
	}
}

func (s *Server) sweepLoop(ctx context.Context) {
	ticker := time.NewTicker(s.sweepInterval)
	defer ticker.Stop()
	for {
		if n, err := s.svc.SweepPending(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.ErrorContext(ctx, "sweep pending", "error", err)
		} else if n > 0 {
			slog.InfoContext(ctx, "appended pending entries", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func ok(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}
