package tlogproof_test

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/thelemail/keylog/pkg/tlogproof"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewPolicyDerivesTheVerifierFromTheSigningKey(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := tlogproof.NewPolicy(tlogproof.PolicyConfig{
		Origin:            testOrigin,
		NoteKeyPath:       writeFile(t, "note.key", skey+"\n"),
		MaxCosignatureAge: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if policy.LogVerifierKey != vkey {
		t.Fatalf("verifier key = %q, want %q", policy.LogVerifierKey, vkey)
	}
	if policy.Origin != testOrigin || policy.WitnessThreshold != 0 || len(policy.WitnessVerifierKeys) != 0 {
		t.Fatalf("policy = %+v", policy)
	}
	if policy.MaxCosignatureAgeSeconds != 86400 {
		t.Fatalf("max age = %d", policy.MaxCosignatureAgeSeconds)
	}
}

func TestNewPolicyRefusesAMismatchedOrIncompleteConfig(t *testing.T) {
	_, vkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	_, otherVkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]tlogproof.PolicyConfig{
		"no key":       {Origin: testOrigin, MaxCosignatureAge: time.Hour},
		"no max age":   {Origin: testOrigin, NoteVerifierKey: vkey},
		"other origin": {Origin: "other.thelemail.com/keys", NoteVerifierKey: vkey, MaxCosignatureAge: time.Hour},
		"policy names another log": {
			Origin:            testOrigin,
			NoteVerifierKey:   vkey,
			WitnessPolicyPath: writeFile(t, "witness-policy", "log "+otherVkey+"\nquorum none\n"),
			MaxCosignatureAge: time.Hour,
		},
		"missing policy file": {
			Origin:            testOrigin,
			NoteVerifierKey:   vkey,
			WitnessPolicyPath: filepath.Join(t.TempDir(), "absent"),
			MaxCosignatureAge: time.Hour,
		},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := tlogproof.NewPolicy(cfg); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
