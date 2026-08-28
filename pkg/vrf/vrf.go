package vrf

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	vrfr255 "filippo.io/mostly-harmless/vrf-r255"
)

type Key struct {
	priv *vrfr255.PrivateKey
}

func Load(path string) (*Key, error) {
	if path == "" {
		return nil, errors.New("vrf: key path required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vrf: read key %s: %w", path, err)
	}
	return Parse(strings.TrimSpace(string(raw)))
}

func Parse(privB64 string) (*Key, error) {
	sk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil {
		return nil, fmt.Errorf("vrf: decode key: %w", err)
	}
	priv, err := vrfr255.NewPrivateKey(sk)
	if err != nil {
		return nil, fmt.Errorf("vrf: parse key: %w", err)
	}
	return &Key{priv: priv}, nil
}

func (k *Key) Prove(alpha []byte) (pi, beta []byte) {
	p := k.priv.Prove(alpha)
	return p.Bytes(), p.Hash()
}

func (k *Key) PublicKeyBytes() []byte {
	return k.priv.PublicKey().Bytes()
}

func (k *Key) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(k.PublicKeyBytes())
}

func GenerateKeyBase64() (privB64, pubB64 string) {
	priv := vrfr255.GenerateKey()
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
}

func ProofHash(pi []byte) ([]byte, error) {
	proof, err := vrfr255.NewProof(pi)
	if err != nil {
		return nil, fmt.Errorf("vrf: parse proof: %w", err)
	}
	return proof.Hash(), nil
}

func Verify(pubB64 string, pi, alpha []byte) (beta []byte, err error) {
	pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil {
		return nil, fmt.Errorf("vrf: decode public key: %w", err)
	}
	pub, err := vrfr255.NewPublicKey(pk)
	if err != nil {
		return nil, fmt.Errorf("vrf: parse public key: %w", err)
	}
	proof, err := vrfr255.NewProof(pi)
	if err != nil {
		return nil, fmt.Errorf("vrf: parse proof: %w", err)
	}
	beta, err = pub.Verify(proof, alpha)
	if err != nil {
		return nil, fmt.Errorf("vrf: %w", err)
	}
	return beta, nil
}
