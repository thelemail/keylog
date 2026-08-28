package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"filippo.io/torchwood"
	"github.com/spf13/cobra"

	keylog "github.com/thelemail/keylog/internal"
	"github.com/thelemail/keylog/internal/entity"
	"github.com/thelemail/keylog/internal/pkg/tlogstore"
	"github.com/thelemail/keylog/pkg/tlogproof"
	"github.com/thelemail/keylog/pkg/vrf"
)

type importLine struct {
	Index      int64     `json:"index"`
	Label      string    `json:"label"`
	Record     []byte    `json:"record"`
	Metadata   []byte    `json:"metadata"`
	VRFProof   []byte    `json:"vrfProof"`
	IncludedAt time.Time `json:"includedAt"`
}

func newImportCmd() *cobra.Command {
	var from string
	var batchSize int
	var skipVerify bool
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Load already-logged entries from a JSONL export without appending to the log",
		Long: "Reads one JSON object per line: {index, label, record, metadata, vrfProof, includedAt}.\n" +
			"Every entry is checked against the log's own inclusion proof before it is stored, so an\n" +
			"export that does not match the tiles is rejected rather than imported.",
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			app, cleanup, err := keylog.NewApp(c.Context(), cfg, false)
			if err != nil {
				return err
			}
			defer cleanup()

			var builder *tlogproof.Builder
			if !skipVerify {
				policy, err := tlogproof.NewPolicy(tlogstore.PolicyConfig(cfg.Log))
				if err != nil {
					return err
				}
				tiles, err := torchwood.NewTileFS(os.DirFS(cfg.Log.Path))
				if err != nil {
					return fmt.Errorf("tile fs: %w", err)
				}
				builder, err = tlogproof.NewBuilder(tlogproof.BuilderConfig{
					MaxCosignatureAge: cfg.Log.MaxCosignatureAge,
					Policy:            policy,
					Tiles:             tiles,
				})
				if err != nil {
					return err
				}
			}

			f, err := os.Open(from)
			if err != nil {
				return fmt.Errorf("open export: %w", err)
			}
			defer func() { _ = f.Close() }()

			var signed []byte
			var checkpoint torchwood.Checkpoint
			if builder != nil {
				signed, checkpoint, err = builder.Checkpoint(c.Context())
				if err != nil {
					return fmt.Errorf("read checkpoint: %w", err)
				}
			}

			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
			batch := make([]entity.Entry, 0, batchSize)
			total, imported, line := 0, 0, 0
			flush := func() error {
				if len(batch) == 0 {
					return nil
				}
				n, err := app.Entries.Import(c.Context(), batch)
				if err != nil {
					return err
				}
				imported += n
				batch = batch[:0]
				return nil
			}

			for scanner.Scan() {
				line++
				raw := scanner.Bytes()
				if len(raw) == 0 {
					continue
				}
				var in importLine
				if err := json.Unmarshal(raw, &in); err != nil {
					return fmt.Errorf("line %d: %w", line, err)
				}
				e, err := toEntry(in)
				if err != nil {
					return fmt.Errorf("line %d: %w", line, err)
				}
				if builder != nil {
					if _, err := builder.BuildAt(c.Context(), signed, checkpoint, in.Index, e.Leaf, in.VRFProof); err != nil {
						return fmt.Errorf("line %d: entry %d is not in the log as exported: %w", line, in.Index, err)
					}
				}
				batch = append(batch, e)
				total++
				if len(batch) >= batchSize {
					if err := flush(); err != nil {
						return err
					}
					fmt.Fprintf(c.OutOrStdout(), "imported %d/%d...\n", imported, total)
				}
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("read export: %w", err)
			}
			if err := flush(); err != nil {
				return err
			}

			count, err := app.Entries.Count(c.Context())
			if err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "read %d entries, inserted %d, table now holds %d\n", total, imported, count)
			if builder != nil {
				fmt.Fprintf(c.OutOrStdout(), "checkpoint tree size: %d\n", checkpoint.N)
				if count > checkpoint.N {
					return fmt.Errorf("table holds %d entries but the checkpoint covers only %d", count, checkpoint.N)
				}
				if count < checkpoint.N {
					fmt.Fprintf(c.OutOrStdout(),
						"%d leaves in the log have no imported record; the log is append-only, so entries whose source rows were deleted stay in it\n",
						checkpoint.N-count)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "Path to the JSONL export (required)")
	cmd.Flags().IntVar(&batchSize, "batch", 500, "Rows per transaction")
	cmd.Flags().BoolVar(&skipVerify, "skip-verify", false, "Do not check each entry against the log's inclusion proof")
	_ = cmd.MarkFlagRequired("from")
	return cmd
}

func toEntry(in importLine) (entity.Entry, error) {
	if in.Label == "" {
		return entity.Entry{}, fmt.Errorf("label is empty")
	}
	if len(in.Record) == 0 {
		return entity.Entry{}, fmt.Errorf("record is empty")
	}
	beta, err := vrf.ProofHash(in.VRFProof)
	if err != nil {
		return entity.Entry{}, err
	}
	index := in.Index
	includedAt := in.IncludedAt.UTC()
	return entity.Entry{
		LabelHash:   tlogproof.LabelHash(in.Label),
		Leaf:        tlogproof.LeafHash(beta, in.Record),
		Record:      in.Record,
		Metadata:    in.Metadata,
		VRFProof:    in.VRFProof,
		Index:       &index,
		SubmittedAt: includedAt,
		IncludedAt:  &includedAt,
	}, nil
}
