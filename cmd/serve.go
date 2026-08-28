package cmd

import (
	"github.com/spf13/cobra"

	keylog "github.com/thelemail/keylog/internal"
	"github.com/thelemail/keylog/internal/runtime"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Serve the tlog-tiles read API, the monitor endpoint and the submission API",
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			app, cleanup, err := keylog.NewApp(c.Context(), cfg, true)
			if err != nil {
				return err
			}
			defer cleanup()
			return runtime.Run(c.Context(), cfg.HTTP.ShutdownTimeout, keylog.NewServer(app))
		},
	}
}
