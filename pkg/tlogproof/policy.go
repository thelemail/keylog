package tlogproof

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
)

type PolicyConfig struct {
	Origin            string
	NoteVerifierKey   string
	NoteKeyPath       string
	WitnessPolicyPath string
}

func NewPolicy(cfg PolicyConfig) (torchwood.Policy, error) {
	if cfg.WitnessPolicyPath != "" {
		raw, err := os.ReadFile(cfg.WitnessPolicyPath)
		if err != nil {
			return nil, fmt.Errorf("tlogproof: read witness policy %s: %w", cfg.WitnessPolicyPath, err)
		}
		policy, err := torchwood.ParsePolicy(raw)
		if err != nil {
			return nil, fmt.Errorf("tlogproof: parse witness policy: %w", err)
		}
		return policy, nil
	}
	verifier, err := NewVerifier(cfg)
	if err != nil {
		return nil, err
	}
	return torchwood.ThresholdPolicy(2,
		torchwood.OriginPolicy(cfg.Origin),
		torchwood.SingleVerifierPolicy(verifier),
	), nil
}

func NewVerifier(cfg PolicyConfig) (note.Verifier, error) {
	if cfg.NoteVerifierKey != "" {
		verifier, err := note.NewVerifier(strings.TrimSpace(cfg.NoteVerifierKey))
		if err != nil {
			return nil, fmt.Errorf("tlogproof: parse note verifier key: %w", err)
		}
		return verifier, nil
	}
	if cfg.NoteKeyPath != "" {
		raw, err := os.ReadFile(cfg.NoteKeyPath)
		if err != nil {
			return nil, fmt.Errorf("tlogproof: read note key %s: %w", cfg.NoteKeyPath, err)
		}
		verifier, err := torchwood.NewVerifierFromSigner(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("tlogproof: derive verifier from note key: %w", err)
		}
		return verifier, nil
	}
	return nil, errors.New("tlogproof: note verifier key or note key path required")
}
