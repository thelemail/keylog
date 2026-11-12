package tlogproof

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/thelemail/trust/tlog"
	"golang.org/x/mod/sumdb/note"
)

type PolicyConfig struct {
	Origin            string
	NoteVerifierKey   string
	NoteKeyPath       string
	WitnessPolicyPath string
	MaxCosignatureAge time.Duration
}

func NewPolicy(cfg PolicyConfig) (tlog.Policy, error) {
	if cfg.MaxCosignatureAge <= 0 {
		return tlog.Policy{}, errors.New("tlogproof: max cosignature age must be positive")
	}
	vkey, err := verifierKey(cfg)
	if err != nil {
		return tlog.Policy{}, err
	}
	base := tlog.Policy{
		Origin:                   cfg.Origin,
		LogVerifierKey:           vkey,
		MaxCosignatureAgeSeconds: int64(cfg.MaxCosignatureAge / time.Second),
	}
	text := []byte("log " + vkey + "\nquorum none\n")
	if cfg.WitnessPolicyPath != "" {
		text, err = os.ReadFile(cfg.WitnessPolicyPath)
		if err != nil {
			return tlog.Policy{}, fmt.Errorf("tlogproof: read witness policy %s: %w", cfg.WitnessPolicyPath, err)
		}
	}
	policy, err := tlog.ParseWitnessPolicy(text, base)
	if err != nil {
		return tlog.Policy{}, fmt.Errorf("tlogproof: parse witness policy: %w", err)
	}
	return policy, nil
}

func verifierKey(cfg PolicyConfig) (string, error) {
	if cfg.NoteVerifierKey != "" {
		vkey := strings.TrimSpace(cfg.NoteVerifierKey)
		if _, err := note.NewVerifier(vkey); err != nil {
			return "", fmt.Errorf("tlogproof: parse note verifier key: %w", err)
		}
		return vkey, nil
	}
	if cfg.NoteKeyPath != "" {
		raw, err := os.ReadFile(cfg.NoteKeyPath)
		if err != nil {
			return "", fmt.Errorf("tlogproof: read note key %s: %w", cfg.NoteKeyPath, err)
		}
		vkey, err := verifierKeyFromSigner(strings.TrimSpace(string(raw)))
		if err != nil {
			return "", fmt.Errorf("tlogproof: derive verifier from note key: %w", err)
		}
		return vkey, nil
	}
	return "", errors.New("tlogproof: note verifier key or note key path required")
}

func verifierKeyFromSigner(skey string) (string, error) {
	signer, err := note.NewSigner(skey)
	if err != nil {
		return "", err
	}
	parts := strings.SplitN(skey, "+", 5)
	if len(parts) != 5 {
		return "", errors.New("malformed note key")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil || len(raw) != 1+ed25519.SeedSize || raw[0] != 1 {
		return "", errors.New("note key is not an Ed25519 key")
	}
	pub, ok := ed25519.NewKeyFromSeed(raw[1:]).Public().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("note key is not an Ed25519 key")
	}
	return note.NewEd25519VerifierKey(signer.Name(), pub)
}
