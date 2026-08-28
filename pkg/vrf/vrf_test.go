package vrf

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestProveVerifyRoundTrip(t *testing.T) {
	privB64, pubB64 := GenerateKeyBase64()
	keyPath := filepath.Join(t.TempDir(), "vrf.key")
	if err := os.WriteFile(keyPath, []byte(privB64+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := Load(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if key.PublicKeyBase64() != pubB64 {
		t.Fatal("loaded key does not carry the generated public key")
	}

	alpha := []byte("vlad@thelemail.com")
	pi, beta := key.Prove(alpha)
	if len(beta) != 64 {
		t.Fatalf("beta length = %d, want 64", len(beta))
	}

	got, err := Verify(pubB64, pi, alpha)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !bytes.Equal(got, beta) {
		t.Fatal("verified beta does not match proved beta")
	}

	hashed, err := ProofHash(pi)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hashed, beta) {
		t.Fatal("ProofHash does not match the proved beta")
	}

	pi2, beta2 := key.Prove(alpha)
	if !bytes.Equal(pi, pi2) || !bytes.Equal(beta, beta2) {
		t.Fatal("prove is not deterministic")
	}

	if _, err := Verify(pubB64, pi, []byte("other@thelemail.com")); err == nil {
		t.Fatal("verify accepted wrong alpha")
	}

	tampered := bytes.Clone(pi)
	tampered[0] ^= 0x01
	if _, err := Verify(pubB64, tampered, alpha); err == nil {
		t.Fatal("verify accepted tampered proof")
	}
}
