package cmd

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/mod/sumdb/note"

	"github.com/thelemail/keylog/pkg/vrf"
)

func newGenerateKeysCmd() *cobra.Command {
	var noteOut, vrfOut, origin string
	cmd := &cobra.Command{
		Use:   "generate-keys",
		Short: "Generate the checkpoint note keypair and the VRF keypair",
		RunE: func(c *cobra.Command, _ []string) error {
			skey, vkey, err := note.GenerateKey(rand.Reader, origin)
			if err != nil {
				return fmt.Errorf("generate note key: %w", err)
			}
			if err := os.WriteFile(noteOut, []byte(skey+"\n"), 0o600); err != nil {
				return fmt.Errorf("write note key: %w", err)
			}
			vrfPriv, vrfPub := vrf.GenerateKeyBase64()
			if err := os.WriteFile(vrfOut, []byte(vrfPriv+"\n"), 0o600); err != nil {
				return fmt.Errorf("write vrf key: %w", err)
			}
			out := c.OutOrStdout()
			fmt.Fprintf(out, "wrote note signing key to %s\n", noteOut)
			fmt.Fprintf(out, "wrote VRF private key to %s\n\n", vrfOut)
			fmt.Fprintf(out, "checkpoint origin:  %s\n", origin)
			fmt.Fprintf(out, "note verifier key:  %s\n", vkey)
			fmt.Fprintf(out, "VRF public key:     %s\n\n", vrfPub)
			fmt.Fprintf(out, "Server environment:\n")
			fmt.Fprintf(out, "KEYLOG_ORIGIN=%s\n", origin)
			fmt.Fprintf(out, "KEYLOG_NOTE_KEY_PATH=%s\n", noteOut)
			fmt.Fprintf(out, "KEYLOG_NOTE_VERIFIER_KEY=%s\n", vkey)
			fmt.Fprintf(out, "KEYLOG_VRF_KEY_PATH=%s\n\n", vrfOut)
			fmt.Fprintf(out, "Clients pin the note verifier key and the VRF public key above.\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&noteOut, "out-note-key", "./dev-note.key", "Path to write the note signing key")
	cmd.Flags().StringVar(&vrfOut, "out-vrf-key", "./dev-vrf.key", "Path to write the VRF private key (base64)")
	cmd.Flags().StringVar(&origin, "origin", "example.com/keys", "Checkpoint origin line (also the note key name)")
	return cmd
}
