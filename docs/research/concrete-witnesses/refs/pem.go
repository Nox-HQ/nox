package refs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"math/rand"
	"strings"
)

// PEMPrivateKey models RFC 7468's textual encoding and, for the body, the
// standards that define each private-key structure. The body is decoded and
// parsed: "is private-key material" is a claim about the bytes, which a
// header line alone cannot establish. The RSA private-key case is the warning
// here: the reference must not stand in an assumption for the structure, so
// it parses the structure.
var PEMPrivateKey = Format{
	Name:        "pem-private-key",
	Proposition: "x is PEM-armoured private-key material (cleartext or encrypted)",
	Sources: []Source{
		{"https://www.rfc-editor.org/rfc/rfc7468#section-2", "boundary lines, label grammar; generators MUST repeat the label on END, parsers MAY disregard it"},
		{"https://www.rfc-editor.org/rfc/rfc7468#section-10", "PRIVATE KEY = PKCS #8 / OneAsymmetricKey"},
		{"https://www.rfc-editor.org/rfc/rfc7468#section-11", "ENCRYPTED PRIVATE KEY = EncryptedPrivateKeyInfo"},
		{"https://www.rfc-editor.org/rfc/rfc5915#section-4", "EC PRIVATE KEY = ECPrivateKey"},
		{"https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.2", "RSAPrivateKey structure (the RSA PRIVATE KEY label itself is OpenSSL convention, not in any RFC)"},
		{"https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key", "AUTH_MAGIC openssh-key-v1 (the armour label is sshkey.c code only)"},
	},
	Claims: []string{"SEC-004", "SEC-299", "SEC-390", "SEC-391", "SEC-426", "SEC-427"},
	Hosts: []Host{
		HostRaw,
		{Name: "yaml-block-scalar", Ext: "yaml", Wrap: func(c string) (string, int) {
			pre := "tls:\n  key: |\n"
			var b strings.Builder
			b.WriteString(pre)
			for _, l := range strings.SplitAfter(c, "\n") {
				if l != "" {
					b.WriteString("    " + l)
				}
			}
			return b.String(), len(pre)
		}},
		{Name: "json-escaped", Ext: "json", Wrap: func(c string) (string, int) {
			pre := `{"private_key": "`
			esc := strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(c)
			return pre + esc + "\"}\n", len(pre)
		}},
	},
	Check: pemViolation,
	Valid: func(r *rand.Rand) []Named {
		return []Named{
			{"pkcs8-ed25519", pemBlock("PRIVATE KEY", pkcs8Ed25519(r), 64, "\n")},
			{"pkcs8-ec-p256", pemBlock("PRIVATE KEY", pkcs8EC(r), 64, "\n")},
			{"sec1-ec", pemBlock("EC PRIVATE KEY", sec1EC(r), 64, "\n")},
			{"pkcs1-rsa", pemBlock("RSA PRIVATE KEY", pkcs1RSA(r), 64, "\n")},
			{"encrypted-pkcs8", pemBlock("ENCRYPTED PRIVATE KEY", encryptedPKCS8(r), 64, "\n")},
			{"openssh", pemBlock("OPENSSH PRIVATE KEY", opensshBlob(r), 70, "\n")},
			{"pkcs8-crlf", pemBlock("PRIVATE KEY", pkcs8Ed25519(r), 64, "\r\n")},
			{"pkcs8-76-columns", pemBlock("PRIVATE KEY", pkcs8EC(r), 76, "\n")},
		}
	},
	Mutate: func(r *rand.Rand, v string) []Named {
		lines := strings.Split(strings.TrimRight(v, "\n"), "\n")
		begin, end := lines[0], lines[len(lines)-1]
		body := lines[1 : len(lines)-1]
		return []Named{
			{"end-label-mismatch", strings.Replace(v, end, "-----END PUBLIC KEY-----", 1)},
			{"end-missing", strings.Join(lines[:len(lines)-1], "\n") + "\n"},
			{"body-placeholder", begin + "\n...\n" + end + "\n"},
			{"body-ellipsis-prose", begin + "\n<your key here>\n" + end + "\n"},
			{"body-truncated", begin + "\n" + strings.Join(body[:(len(body)+1)/2], "\n") + "\n" + end + "\n"},
			{"public-key-label", strings.NewReplacer("PRIVATE KEY", "PUBLIC KEY").Replace(v)},
		}
	},
	Limits: []string{
		"RSA PRIVATE KEY and OPENSSH PRIVATE KEY labels are convention/code, not RFC text",
		"RFC 7468 lax parsing (whitespace inside base64) is accepted; Proc-Type encrypted legacy PEM is out of scope",
		"key material is generated from a seeded RNG; it is structurally valid, never a real key",
	},
}

func pemBlock(label string, der []byte, width int, eol string) string {
	var b strings.Builder
	b.WriteString("-----BEGIN " + label + "-----" + eol)
	s := base64.StdEncoding.EncodeToString(der)
	for len(s) > width {
		b.WriteString(s[:width] + eol)
		s = s[width:]
	}
	b.WriteString(s + eol)
	b.WriteString("-----END " + label + "-----" + eol)
	return b.String()
}

func pemViolation(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) < 3 {
		return "structure"
	}
	label, ok := boundary(lines[0], "BEGIN")
	if !ok {
		return "begin-boundary"
	}
	endLabel, ok := boundary(lines[len(lines)-1], "END")
	if !ok {
		return "end-boundary"
	}
	// Generators MUST repeat the label; a mismatch is not something any
	// conforming generator emits, so the reference rejects it.
	if endLabel != label {
		return "label-mismatch"
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(strings.Join(lines[1:len(lines)-1], "")), ""))
	if err != nil {
		return "base64"
	}
	switch label {
	case "PRIVATE KEY":
		if _, err := x509.ParsePKCS8PrivateKey(der); err != nil {
			return "pkcs8"
		}
	case "EC PRIVATE KEY":
		if _, err := x509.ParseECPrivateKey(der); err != nil {
			return "sec1"
		}
	case "RSA PRIVATE KEY":
		if _, err := x509.ParsePKCS1PrivateKey(der); err != nil {
			return "pkcs1"
		}
	case "ENCRYPTED PRIVATE KEY":
		var epki struct {
			Alg  pkix.AlgorithmIdentifier
			Data []byte
		}
		if rest, err := asn1.Unmarshal(der, &epki); err != nil || len(rest) != 0 || len(epki.Data) == 0 {
			return "encrypted-pkcs8"
		}
	case "OPENSSH PRIVATE KEY":
		if !bytes.HasPrefix(der, []byte("openssh-key-v1\x00")) {
			return "openssh-magic"
		}
	default:
		return "label"
	}
	return ""
}

func boundary(line, kind string) (string, bool) {
	line = strings.TrimRight(line, " \t")
	pre, post := "-----"+kind+" ", "-----"
	if !strings.HasPrefix(line, pre) || !strings.HasSuffix(line, post) || len(line) < len(pre)+len(post) {
		return "", false
	}
	return line[len(pre) : len(line)-len(post)], true
}

// Deterministic key material. crypto/rand-driven generators in the standard
// library ignore a supplied reader's determinism, so keys are built from
// seeded scalars and primes directly.

func pkcs8Ed25519(r *rand.Rand) []byte {
	seed := make([]byte, ed25519.SeedSize)
	r.Read(seed)
	der, _ := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(seed))
	return der
}

func ecKey(r *rand.Rand) *ecdsa.PrivateKey {
	c := elliptic.P256()
	d := new(big.Int).Rand(r, new(big.Int).Sub(c.Params().N, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	b := make([]byte, 32)
	d.FillBytes(b)
	k, err := ecdsa.ParseRawPrivateKey(c, b)
	if err != nil {
		panic(err)
	}
	return k
}

func pkcs8EC(r *rand.Rand) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(ecKey(r))
	if err != nil {
		panic(err)
	}
	return der
}

func sec1EC(r *rand.Rand) []byte {
	der, err := x509.MarshalECPrivateKey(ecKey(r))
	if err != nil {
		panic(err)
	}
	return der
}

func prime(r *rand.Rand, bits int) *big.Int {
	for {
		p := new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
		p.SetBit(p, bits-1, 1).SetBit(p, bits-2, 1).SetBit(p, 0, 1)
		if p.ProbablyPrime(32) {
			return p
		}
	}
}

func pkcs1RSA(r *rand.Rand) []byte {
	e := big.NewInt(65537)
	for {
		p, q := prime(r, 1024), prime(r, 1024)
		one := big.NewInt(1)
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
		d := new(big.Int).ModInverse(e, phi)
		if d == nil || p.Cmp(q) == 0 {
			continue
		}
		k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 65537}, D: d, Primes: []*big.Int{p, q}}
		k.Precompute()
		if k.Validate() != nil {
			continue
		}
		return x509.MarshalPKCS1PrivateKey(k)
	}
}

func encryptedPKCS8(r *rand.Rand) []byte {
	ct := make([]byte, 144)
	r.Read(ct)
	der, _ := asn1.Marshal(struct {
		Alg  pkix.AlgorithmIdentifier
		Data []byte
	}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}}, ct})
	return der
}

func opensshBlob(r *rand.Rand) []byte {
	b := []byte("openssh-key-v1\x00")
	rest := make([]byte, 300)
	r.Read(rest)
	return append(b, rest...)
}
