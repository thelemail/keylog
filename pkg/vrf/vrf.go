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
