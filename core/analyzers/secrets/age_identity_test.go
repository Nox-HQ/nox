package secrets

import (
	"context"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/discovery"
)

// age identities, per the C2SP age spec (github.com/C2SP/C2SP, age.md):
//
//	An X25519 identity is ... encoded as Bech32 with HRP AGE-SECRET-KEY-.
//	An MLKEM768-X25519 identity is ... encoded as Bech32 with HRP
//	AGE-SECRET-KEY-PQ-.
//	Bech32 strings can only be all uppercase or all lowercase, but the
//	checksum is always computed over the lowercase string.
//
// SEC-077 was written before the post-quantum identity existed and hard-coded
// the X25519 HRP, so the spec's own PQ example produced no finding at all in an
// age-keygen keys file (concrete-witness research, #814).

// The spec's published examples. They are the only vectors here not produced by
// this file's own encoder, which is what makes the checksum tests below more
// than an encoder agreeing with itself.
const (
	ageSpecX25519 = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"
	ageSpecPQ     = "AGE-SECRET-KEY-PQ-1XX76JRALNLXDMEW0CRK45QMCCH4X06SE84UN3VPM33W6HWDX0H3SK3ZQFR"
)

// testBech32Encode is BIP-173's reference encoder, written here independently
// of the implementation under test so the seeded identities are not produced
// by the code that checks them.
func testBech32Encode(hrp string, payload []byte) string {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	var data []byte
	acc, bits := 0, 0
	for _, b := range payload {
		acc = acc<<8 | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			data = append(data, byte(acc>>bits&31))
		}
	}
	if bits > 0 {
		data = append(data, byte(acc<<(5-bits)&31))
	}
	polymod := func(v []byte) int {
		gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
		chk := 1
		for _, x := range v {
			top := chk >> 25
			chk = (chk&0x1ffffff)<<5 ^ int(x)
			for i := range 5 {
				if top>>i&1 == 1 {
					chk ^= gen[i]
				}
			}
		}
		return chk
	}
	var exp []byte
	for i := range len(hrp) {
		exp = append(exp, hrp[i]>>5)
	}
	exp = append(exp, 0)
	for i := range len(hrp) {
		exp = append(exp, hrp[i]&31)
	}
	mod := polymod(append(append(exp, data...), 0, 0, 0, 0, 0, 0)) ^ 1
	var b strings.Builder
	b.WriteString(hrp + "1")
	for _, d := range data {
		b.WriteByte(charset[d])
	}
	for i := range 6 {
		b.WriteByte(charset[mod>>(5*(5-i))&31])
	}
	return b.String()
}

// seededAgeIdentities returns identities of both kinds from a fixed seed, in
// the upper case age-keygen writes.
func seededAgeIdentities(t *testing.T) map[string]string {
	t.Helper()
	r := rand.New(rand.NewSource(814))
	out := map[string]string{}
	for name, hrp := range map[string]string{"x25519": "age-secret-key-", "pq": "age-secret-key-pq-"} {
		key := make([]byte, 32)
		r.Read(key)
		out[name] = strings.ToUpper(testBech32Encode(hrp, key))
	}
	return out
}

func sec077Lines(t *testing.T, name, content string) int {
	t.Helper()
	dir := t.TempDir()
	path := writeFile(t, dir, name, content)
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: filepath.Base(path), AbsPath: path}})
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}
	n := 0
	for _, f := range fs.Findings() {
		if f.RuleID == "SEC-077" {
			n++
		}
	}
	return n
}

// keysFile is the shape age-keygen writes: a comment header, then the identity.
func keysFile(identity string) string {
	return "# created: 2026-10-04T12:00:00+02:00\n# public key: age1...\n" + identity + "\n"
}

func TestSEC077ReportsBothIdentityKinds(t *testing.T) {
	ids := seededAgeIdentities(t)
	cases := map[string]string{
		"spec-x25519":   ageSpecX25519,
		"spec-pq":       ageSpecPQ,
		"seeded-x25519": ids["x25519"],
		"seeded-pq":     ids["pq"],
	}
	for name, id := range cases {
		for host, content := range map[string]string{
			"keys.txt":  keysFile(id),
			"notes.md":  "Rotated `" + id + "` today.\n",
			"export.sh": "export SOPS_AGE_KEY=" + id + "\n",
		} {
			if got := sec077Lines(t, host, content); got != 1 {
				t.Errorf("%s in %s: %d SEC-077 findings, want 1", name, host, got)
			}
		}
	}
}

// Bech32 is single-case, either case (BIP-173). Nothing known emits a
// lowercase age identity, but the spec permits one and age's parser accepts
// it, so a lowercase identity is still a secret key.
func TestSEC077ReportsLowercaseIdentities(t *testing.T) {
	for name, id := range seededAgeIdentities(t) {
		if got := sec077Lines(t, "keys.txt", keysFile(strings.ToLower(id))); got != 1 {
			t.Errorf("lowercase %s: %d SEC-077 findings, want 1", name, got)
		}
	}
}

// Mixed case is not Bech32, so it is not an identity of either kind.
func TestSEC077IgnoresMixedCase(t *testing.T) {
	id := seededAgeIdentities(t)["x25519"]
	mixed := strings.ToLower(id[:20]) + id[20:]
	if got := sec077Lines(t, "keys.txt", keysFile(mixed)); got != 0 {
		t.Errorf("mixed-case identity: %d SEC-077 findings, want 0", got)
	}
}

// TestAgeChecksumAgainstSpecExamples licenses verifyAgeIdentity the way the
// published-token test licenses the GitHub checksum: against vectors this
// package did not generate.
func TestAgeChecksumAgainstSpecExamples(t *testing.T) {
	for _, id := range []string{ageSpecX25519, ageSpecPQ, strings.ToLower(ageSpecPQ)} {
		consistent, applicable := verifyAgeIdentity(id)
		if !applicable || !consistent {
			t.Errorf("%s: applicable=%v consistent=%v, want both true", id, applicable, consistent)
		}
	}
}

func TestAgeChecksumRejectsATamperedIdentity(t *testing.T) {
	// One data character changed: Bech32 detects every single substitution.
	tampered := ageSpecPQ[:30] + "Q" + ageSpecPQ[31:]
	if tampered == ageSpecPQ {
		tampered = ageSpecPQ[:30] + "P" + ageSpecPQ[31:]
	}
	consistent, applicable := verifyAgeIdentity(tampered)
	if !applicable {
		t.Fatal("the check did not apply to a well-formed identity")
	}
	if consistent {
		t.Error("a tampered identity verified; the checksum is not being computed")
	}
	// All-zero data, which SEC-077 matches and no generator can produce.
	zeros := "AGE-SECRET-KEY-1" + strings.Repeat("0", 58)
	if c, a := verifyAgeIdentity(zeros); !a || c {
		t.Errorf("all-zero identity: applicable=%v consistent=%v, want true,false", a, c)
	}
}

func TestAgeChecksumInapplicableValuesProduceNoVerdict(t *testing.T) {
	for _, v := range []string{
		"",
		"AGE-SECRET-KEY-",
		"AGE-SECRET-KEY-1TOOSHORT",
		// A recipient, not an identity.
		"age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq",
		// Mixed case is not Bech32.
		strings.ToLower(ageSpecX25519[:20]) + ageSpecX25519[20:],
		// Wrong data length.
		ageSpecX25519 + "Q",
		"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",
	} {
		if _, applicable := verifyAgeIdentity(v); applicable {
			t.Errorf("%q: the check claimed to apply", v)
		}
	}
	// Quotes around the value, as a match may carry them.
	if c, a := verifyAgeIdentity(`"` + ageSpecX25519 + `"`); !a || !c {
		t.Errorf("quoted spec example: applicable=%v consistent=%v", a, c)
	}
}

// The verdict reaches the ledger as static evidence, in both directions, and
// changes nothing a consumer sees: a failed checksum is recorded, not acted on.
func TestAgeChecksumIsRecordedAsStaticEvidence(t *testing.T) {
	for _, tc := range []struct {
		id       string
		supports bool
	}{
		{ageSpecPQ, true},
		{"AGE-SECRET-KEY-1" + strings.Repeat("0", 58), false},
	} {
		n, store := scanWithReasoning(t, "keys.txt", keysFile(tc.id))
		if n != 1 {
			t.Errorf("%s: %d findings, want 1 (the checksum must not change output)", tc.id[:20], n)
		}
		found := false
		for _, subject := range store.Subjects() {
			for _, c := range store.About(subject).Claims {
				if c.Kind == evidence.KindStatic && strings.Contains(c.Statement, "Bech32 checksum") {
					found = true
					if c.Refutes() == tc.supports {
						t.Errorf("%s: claim polarity wrong: %q", tc.id[:20], c.Statement)
					}
				}
			}
		}
		if !found {
			t.Errorf("%s: no static Bech32 checksum claim recorded", tc.id[:20])
		}
	}
}
