package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/thelemail/keylog/internal/config"
)

var (
	cfgOnce sync.Once
	cfgVal  config.Config
	cfgErr  error
)

func loadConfig() (config.Config, error) {
	cfgOnce.Do(func() {
		cfgVal, cfgErr = config.Load()
		if cfgErr != nil {
			cfgErr = fmt.Errorf("load config: %w", cfgErr)
			return
		}
		setupLogger(cfgVal.Logger)
	})
	return cfgVal, cfgErr
}

func setupLogger(cfg config.Logger) {
	opts := &slog.HandlerOptions{Level: parseLevel(cfg.Level)}
	var h slog.Handler
	if strings.EqualFold(cfg.Format, "text") {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "keylog",
		Short:         "A witnessed transparency log for key directories",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(
		newServeCmd(),
		newGenerateKeysCmd(),
		newInfoCmd(),
		newMigrateCmd(),
		newImportCmd(),
		newFixturesCmd(),
		newVersionCmd(),
	)
	return root
}

func Execute(ctx context.Context) error {
	return newRootCmd().ExecuteContext(ctx)
}
