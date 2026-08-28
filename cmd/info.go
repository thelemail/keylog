package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/thelemail/keylog/internal/pkg/tlogstore"
	"github.com/thelemail/keylog/pkg/tlogproof"
	"github.com/thelemail/keylog/pkg/vrf"
)

func newInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show the configured log identity and current checkpoint",
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			fmt.Fprintf(out, "origin:         %s\n", cfg.Log.Origin)
			fmt.Fprintf(out, "path:           %s\n", cfg.Log.Path)
			fmt.Fprintf(out, "witness policy: %s\n", orNone(cfg.Log.WitnessPolicyPath))
			if verifier, err := tlogproof.NewVerifier(tlogstore.PolicyConfig(cfg.Log)); err == nil {
				fmt.Fprintf(out, "note verifier:  %s\n", verifier.Name())
			}
			if key, err := vrf.Load(cfg.Log.VRFKeyPath); err == nil {
				fmt.Fprintf(out, "vrf public key: %s\n", key.PublicKeyBase64())
			}
			raw, err := os.ReadFile(filepath.Join(cfg.Log.Path, "checkpoint"))
			if err != nil {
				fmt.Fprintf(out, "checkpoint: none (%v)\n", err)
				return nil
			}
			fmt.Fprintf(out, "checkpoint:\n%s", raw)
			return nil
		},
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none — unwitnessed, log signature only)"
	}
	return s
}
