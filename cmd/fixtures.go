package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/torchwood"
	"github.com/spf13/cobra"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/thelemail/keylog/internal/config"
	"github.com/thelemail/keylog/internal/pkg/tlogstore"
	"github.com/thelemail/keylog/pkg/tlogproof"
	"github.com/thelemail/keylog/pkg/vrf"
)

type fixturePolicy struct {
	Origin                   string   `json:"origin"`
	LogVerifierKey           string   `json:"logVerifierKey"`
	VRFPublicKey             string   `json:"vrfPublicKey"`
	WitnessVerifierKeys      []string `json:"witnessVerifierKeys"`
	WitnessThreshold         int      `json:"witnessThreshold"`
	MaxCosignatureAgeSeconds int64    `json:"maxCosignatureAgeSeconds"`
}

type fixtureCase struct {
	Name   string        `json:"name"`
	Label  string        `json:"label"`
	Record string        `json:"record"`
	Proof  string        `json:"proof"`
	Policy fixturePolicy `json:"policy"`
	Expect string        `json:"expect"`
}

type fixtureFile struct {
	NowUnix int64         `json:"nowUnix"`
	Cases   []fixtureCase `json:"cases"`
}

func newFixturesCmd() *cobra.Command {
	var outPath, origin string
	cmd := &cobra.Command{
		Use:   "fixtures",
		Short: "Generate client test vectors for proof verification",
		RunE: func(c *cobra.Command, _ []string) error {
			file, err := generateFixtures(c.Context(), origin)
			if err != nil {
				return err
			}
			raw, err := json.MarshalIndent(file, "", "  ")
			if err != nil {
				return err
			}
			raw = append(raw, '\n')
			if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
				return err
			}
			if err := os.WriteFile(outPath, raw, 0o600); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "wrote %d cases to %s\n", len(file.Cases), outPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "./fixtures.json", "Output path for the fixture JSON")
	cmd.Flags().StringVar(&origin, "origin", "test.thelemail.com/keys", "Checkpoint origin used by the fixtures")
	return cmd
}

func generateFixtures(ctx context.Context, origin string) (fixtureFile, error) {
	now := time.Now().UTC().Truncate(time.Second)
	dir, err := os.MkdirTemp("", "keylog-fixtures")
	if err != nil {
		return fixtureFile{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		return fixtureFile{}, err
	}
	notePath := filepath.Join(dir, "note.key")
	if err := os.WriteFile(notePath, []byte(skey+"\n"), 0o600); err != nil {
		return fixtureFile{}, err
	}
	vrfPriv, vrfPub := vrf.GenerateKeyBase64()
	vrfPath := filepath.Join(dir, "vrf.key")
	if err := os.WriteFile(vrfPath, []byte(vrfPriv+"\n"), 0o600); err != nil {
		return fixtureFile{}, err
	}
	cfg := config.Log{
		Path:               filepath.Join(dir, "log"),
		Origin:             origin,
		NoteKeyPath:        notePath,
		NoteVerifierKey:    vkey,
		VRFKeyPath:         vrfPath,
		CheckpointInterval: 100 * time.Millisecond,
		MaxCosignatureAge:  24 * time.Hour,
	}

	log, err := tlogstore.New(ctx, cfg)
	if err != nil {
		return fixtureFile{}, err
	}
	defer func() { _ = log.Shutdown(context.Background()) }()
	vrfKey, err := vrf.Load(vrfPath)
	if err != nil {
		return fixtureFile{}, err
	}

	type entryData struct {
		label  string
		record []byte
		pi     []byte
		index  uint64
	}
	seeds := []struct {
		label   string
		version int
	}{
		{"vlad@thelemail.com", 1},
		{"vlad@thelemail.com", 2},
		{"zoe@thelemail.com", 1},
	}
	var entries []entryData
	for _, s := range seeds {
		record := fmt.Appendf(nil,
			`{"algorithm":"openpgp-curve25519-v6","fingerprint":"%s","issuedAt":"%s","label":"%s","version":%d}`,
			strings.Repeat("ab", 20), now.Add(-time.Hour).Format(time.RFC3339), s.label, s.version)
		pi, beta := vrfKey.Prove([]byte(s.label))
		index, _, err := log.Append(ctx, tlogproof.LeafHash(beta, record))
		if err != nil {
			return fixtureFile{}, err
		}
		entries = append(entries, entryData{label: s.label, record: record, pi: pi, index: index})
	}

	devPolicy := torchwood.ThresholdPolicy(2, torchwood.OriginPolicy(origin), mustSingleVerifier(vkey))
	var signedCheckpoint []byte
	var checkpoint torchwood.Checkpoint
	deadline := time.Now().Add(20 * time.Second)
	for {
		raw, err := os.ReadFile(filepath.Join(cfg.Path, "checkpoint"))
		if err == nil {
			cp, _, err := torchwood.VerifyCheckpoint(raw, devPolicy)
			if err == nil && cp.N >= int64(len(entries)) {
				signedCheckpoint, checkpoint = raw, cp
				break
			}
		}
		if time.Now().After(deadline) {
			return fixtureFile{}, fmt.Errorf("checkpoint never covered all fixture entries")
		}
		time.Sleep(50 * time.Millisecond)
	}

	tiles, err := torchwood.NewTileFS(os.DirFS(cfg.Path))
	if err != nil {
		return fixtureFile{}, err
	}
	prove := func(index uint64, extra, cpBytes []byte) (string, error) {
		hashReader := torchwood.TileHashReaderWithContext(ctx, checkpoint.Tree, tiles)
		p, err := tlog.ProveRecord(checkpoint.N, int64(index), hashReader)
		if err != nil {
			return "", err
		}
		return string(torchwood.FormatProofWithExtraData(int64(index), extra, p, cpBytes)), nil
	}

	logSigner, err := note.NewSigner(skey)
	if err != nil {
		return fixtureFile{}, err
	}
	openNote, err := note.Open(signedCheckpoint, note.VerifierList(mustVerifier(vkey)))
	if err != nil {
		return fixtureFile{}, err
	}

	type witness struct {
		signerFresh note.Signer
		signerStale note.Signer
		vkey        string
	}
	var witnesses []witness
	for i := range 3 {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fixtureFile{}, err
		}
		name := fmt.Sprintf("witness%d.example.org", i+1)
		reference, err := torchwood.NewCosignatureSigner(name, priv)
		if err != nil {
			return fixtureFile{}, err
		}
		witnesses = append(witnesses, witness{
			signerFresh: &fixedTimeCosigner{name: name, hash: reference.KeyHash(), key: priv, ts: uint64(now.Add(-time.Minute).Unix())},
			signerStale: &fixedTimeCosigner{name: name, hash: reference.KeyHash(), key: priv, ts: uint64(now.Add(-72 * time.Hour).Unix())},
			vkey:        reference.Verifier().String(),
		})
	}
	cosign := func(signers ...note.Signer) ([]byte, error) {
		return note.Sign(&note.Note{Text: openNote.Text}, append([]note.Signer{logSigner}, signers...)...)
	}
	witnessed, err := cosign(witnesses[0].signerFresh, witnesses[1].signerFresh)
	if err != nil {
		return fixtureFile{}, err
	}
	oneWitness, err := cosign(witnesses[0].signerFresh)
	if err != nil {
		return fixtureFile{}, err
	}
	staleWitnessed, err := cosign(witnesses[0].signerStale, witnesses[1].signerStale)
	if err != nil {
		return fixtureFile{}, err
	}

	basePolicy := fixturePolicy{
		Origin:                   origin,
		LogVerifierKey:           vkey,
		VRFPublicKey:             vrfPub,
		WitnessThreshold:         0,
		MaxCosignatureAgeSeconds: 86400,
	}
	prodPolicy := basePolicy
	prodPolicy.WitnessVerifierKeys = []string{witnesses[0].vkey, witnesses[1].vkey, witnesses[2].vkey}
	prodPolicy.WitnessThreshold = 2
	wrongOriginPolicy := basePolicy
	wrongOriginPolicy.Origin = "other.example.org/keys"

	e := entries[1]
	validProof, err := prove(e.index, e.pi, signedCheckpoint)
	if err != nil {
		return fixtureFile{}, err
	}
	witnessedProof, err := prove(e.index, e.pi, witnessed)
	if err != nil {
		return fixtureFile{}, err
	}
	oneWitnessProof, err := prove(e.index, e.pi, oneWitness)
	if err != nil {
		return fixtureFile{}, err
	}
	staleProof, err := prove(e.index, e.pi, staleWitnessed)
	if err != nil {
		return fixtureFile{}, err
	}
	otherEntryProof, err := prove(entries[2].index, entries[2].pi, signedCheckpoint)
	if err != nil {
		return fixtureFile{}, err
	}

	tamperVRF := func(offset int) string {
		pi := append([]byte(nil), e.pi...)
		pi[offset] ^= 0x01
		p, err := prove(e.index, pi, signedCheckpoint)
		if err != nil {
			return ""
		}
		return p
	}

	lines := strings.Split(validProof, "\n")
	tamperedIndex := strings.Replace(validProof, fmt.Sprintf("index %d", e.index), fmt.Sprintf("index %d", entries[2].index), 1)
	var tamperedPath string
	for i, l := range lines {
		if i >= 3 && len(l) == 44 && !strings.HasPrefix(l, "index") {
			raw, err := base64.StdEncoding.DecodeString(l)
			if err == nil {
				raw[0] ^= 0x01
				mutated := append([]string(nil), lines...)
				mutated[i] = base64.StdEncoding.EncodeToString(raw)
				tamperedPath = strings.Join(mutated, "\n")
				break
			}
		}
	}

	record := string(e.record)
	cases := []fixtureCase{
		{Name: "ok-dev", Label: e.label, Record: record, Proof: validProof, Policy: basePolicy, Expect: "ok"},
		{Name: "ok-witnessed", Label: e.label, Record: record, Proof: witnessedProof, Policy: prodPolicy, Expect: "ok"},
		{Name: "ok-second-label", Label: entries[2].label, Record: string(entries[2].record), Proof: otherEntryProof, Policy: basePolicy, Expect: "ok"},
		{Name: "witness-threshold-unmet", Label: e.label, Record: record, Proof: oneWitnessProof, Policy: prodPolicy, Expect: "tlog_witness_policy_unmet"},
		{Name: "stale-cosignatures", Label: e.label, Record: record, Proof: staleProof, Policy: prodPolicy, Expect: "tlog_checkpoint_stale"},
		{Name: "wrong-origin-policy", Label: e.label, Record: record, Proof: validProof, Policy: wrongOriginPolicy, Expect: "tlog_checkpoint_unverified"},
		{Name: "tampered-index", Label: e.label, Record: record, Proof: tamperedIndex, Policy: basePolicy, Expect: "tlog_inclusion_invalid"},
		{Name: "tampered-path", Label: e.label, Record: record, Proof: tamperedPath, Policy: basePolicy, Expect: "tlog_inclusion_invalid"},
		{Name: "tampered-record", Label: e.label, Record: strings.Replace(record, "vlad", "eve1", 1), Proof: validProof, Policy: basePolicy, Expect: "tlog_inclusion_invalid"},
		{Name: "vrf-tampered-gamma", Label: e.label, Record: record, Proof: tamperVRF(0), Policy: basePolicy, Expect: "tlog_vrf_invalid"},
		{Name: "vrf-tampered-c", Label: e.label, Record: record, Proof: tamperVRF(40), Policy: basePolicy, Expect: "tlog_vrf_invalid"},
		{Name: "vrf-tampered-s", Label: e.label, Record: record, Proof: tamperVRF(56), Policy: basePolicy, Expect: "tlog_vrf_invalid"},
		{Name: "wrong-label", Label: entries[2].label, Record: record, Proof: validProof, Policy: basePolicy, Expect: "tlog_vrf_invalid"},
		{Name: "truncated-proof", Label: e.label, Record: record, Proof: validProof[:len(validProof)/3], Policy: basePolicy, Expect: "tlog_proof_malformed"},
		{Name: "garbage-proof", Label: e.label, Record: record, Proof: "not a proof at all\n", Policy: basePolicy, Expect: "tlog_proof_malformed"},
		{Name: "missing-proof", Label: e.label, Record: record, Proof: "", Policy: basePolicy, Expect: "tlog_proof_missing"},
	}
	for _, fc := range cases {
		if fc.Proof == "" && fc.Expect != "tlog_proof_missing" {
			return fixtureFile{}, fmt.Errorf("fixture case %s has empty proof", fc.Name)
		}
	}
	return fixtureFile{NowUnix: now.Unix(), Cases: cases}, nil
}

type fixedTimeCosigner struct {
	name string
	hash uint32
	key  ed25519.PrivateKey
	ts   uint64
}

func (s *fixedTimeCosigner) Name() string    { return s.name }
func (s *fixedTimeCosigner) KeyHash() uint32 { return s.hash }

func (s *fixedTimeCosigner) Sign(msg []byte) ([]byte, error) {
	m := fmt.Appendf(nil, "cosignature/v1\ntime %d\n%s", s.ts, msg)
	sig := ed25519.Sign(s.key, m)
	out := make([]byte, 0, 8+ed25519.SignatureSize)
	out = binary.BigEndian.AppendUint64(out, s.ts)
	return append(out, sig...), nil
}

func mustVerifier(vkey string) note.Verifier {
	v, err := note.NewVerifier(vkey)
	if err != nil {
		panic(err)
	}
	return v
}

func mustSingleVerifier(vkey string) torchwood.Policy {
	return torchwood.SingleVerifierPolicy(mustVerifier(vkey))
}
