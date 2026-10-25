package mcpfeed

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/slopfeed"
)

// testdata/feed.json was produced by NOX Intelligence's own
// domain.MCPFeed.Sign (see testdata/generate.go.txt) under a throwaway key whose
// public half is testdata/pub.pem. It is the contract test: if this package's
// canonical bytes, digest or domain prefix ever differ from the service's, the
// service's own feed stops verifying here.
func serviceFeed(t *testing.T) (body []byte, verify slopfeed.SignatureVerifier) {
	t.Helper()
	body, err := os.ReadFile("testdata/feed.json")
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile("testdata/pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	verify, err = slopfeed.PEMEd25519Verifier(pem)
	if err != nil {
		t.Fatal(err)
	}
	return body, verify
}

func TestParseAcceptsTheServicesOwnFeed(t *testing.T) {
	body, verify := serviceFeed(t)
	f, err := Parse(body, verify)
	if err != nil {
		t.Fatalf("the service's own feed does not verify: %v", err)
	}
	if len(f.Entries) != 6 || f.Version != "2026.10.26" {
		t.Errorf("feed = %d entries, version %q", len(f.Entries), f.Version)
	}
}

// edit decodes the service's feed, lets fn change it, and re-encodes it.
func edit(t *testing.T, fn func(*Feed)) []byte {
	t.Helper()
	body, _ := serviceFeed(t)
	var f Feed
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatal(err)
	}
	fn(&f)
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Every check must be independently necessary: each case below passes every
// other check and fails exactly one.
func TestParseFailsClosed(t *testing.T) {
	_, verify := serviceFeed(t)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = otherPub

	resign := func(f *Feed, priv ed25519.PrivateKey, prefix string) {
		content, _ := Canonical(f.Entries)
		f.Digest = Digest(content)
		f.Signature = &Signature{Algorithm: "ed25519", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte(prefix), content...)))}
	}

	cases := []struct {
		name string
		body []byte
		want error
	}{
		{"an entry changed, digest left alone", edit(t, func(f *Feed) { f.Entries[0].Summary = "nothing to see" }), ErrDigest},
		{"an advisory dropped, digest left alone", edit(t, func(f *Feed) { f.Entries = f.Entries[1:] }), ErrDigest},
		{"an entry changed and the digest recomputed, signature left alone", edit(t, func(f *Feed) {
			f.Entries[0].Summary = "nothing to see"
			content, _ := Canonical(f.Entries)
			f.Digest = Digest(content)
		}), ErrSignature},
		{"signed by another key", edit(t, func(f *Feed) { resign(f, otherPriv, SignedContext) }), ErrSignature},
		{"signed without the domain prefix (another feed's signature)", edit(t, func(f *Feed) {
			_, priv, _ := ed25519.GenerateKey(rand.Reader)
			resign(f, priv, "")
		}), ErrSignature},
		{"unsigned", edit(t, func(f *Feed) { f.Signature = nil }), ErrUnsigned},
		{"signature algorithm not ed25519", edit(t, func(f *Feed) { f.Signature.Algorithm = "rsa" }), ErrUnsigned},
		{"another schema", edit(t, func(f *Feed) { f.SchemaVersion = "mcp-advisories/v2" }), ErrSchema},
		{"a malformed signature", edit(t, func(f *Feed) { f.Signature.Value = "!!not-base64!!" }), ErrSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := Parse(c.body, verify)
			if f != nil || !errors.Is(err, c.want) {
				t.Fatalf("Parse = %v, %v; want failure %v", f, err, c.want)
			}
		})
	}
	if _, err := Parse([]byte(`{not json`), verify); err == nil {
		t.Error("malformed JSON must fail")
	}
	body, _ := serviceFeed(t)
	if f, err := Parse(body, nil); f != nil || err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Errorf("a nil verifier is an error, not a skipped check: %v %v", f, err)
	}
}

// The feed's self-described key is not a trust root.
func TestParseIgnoresTheFeedsOwnKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := edit(t, func(f *Feed) {
		content, _ := Canonical(f.Entries)
		f.Signature = &Signature{Algorithm: "ed25519", KeyID: "attacker", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte(SignedContext), content...)))}
	})
	_, verify := serviceFeed(t)
	if _, err := Parse(body, verify); !errors.Is(err, ErrSignature) {
		t.Fatalf("a feed signed by a key the operator did not pin was accepted: %v", err)
	}
	// And the same bytes verify under the key that did sign them.
	own, err := slopfeed.PEMEd25519Verifier([]byte(slopfeed.EncodePublicKeyPEM(pub)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(body, own); err != nil {
		t.Fatalf("control: the signer's own key must verify: %v", err)
	}
}
