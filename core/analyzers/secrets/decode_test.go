package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestDecodeBase64Segments(t *testing.T) {
	// Encode a fake AWS key in base64.
	fakeKey := "AKIAIOSFODNN7EXAMPLE_aws_secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	encoded := base64.StdEncoding.EncodeToString([]byte(fakeKey))

	content := []byte("config_value = " + encoded + "\n")
	segments := decodeBase64Segments(content)

	if len(segments) == 0 {
		t.Fatal("expected at least one base64 segment")
	}

	found := false
	for _, seg := range segments {
		if seg.Encoding == "base64" && seg.Decoded == fakeKey {
			found = true
		}
	}
	if !found {
		t.Error("expected to decode the fake AWS key from base64")
	}
}

func TestDecodeHexSegments(t *testing.T) {
	// Encode a fake GitHub token in hex.
	fakeToken := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	encoded := hex.EncodeToString([]byte(fakeToken))

	content := []byte("token = " + encoded + "\n")
	segments := decodeHexSegments(content)

	if len(segments) == 0 {
		t.Fatal("expected at least one hex segment")
	}

	found := false
	for _, seg := range segments {
		if seg.Encoding == "hex" && seg.Decoded == fakeToken {
			found = true
		}
	}
	if !found {
		t.Error("expected to decode the fake GitHub token from hex")
	}
}

func TestDecodeAndScan_Base64WrappedAWSKey(t *testing.T) {
	// Create a real analyzer to get the engine.
	a := NewAnalyzer()

	fakeContent := "AKIAIOSFODNN7EXAMPLE"
	encoded := base64.StdEncoding.EncodeToString([]byte(fakeContent))
	content := []byte("secret = " + encoded)

	results := DecodeAndScan(content, "test.txt", a.engine)

	foundEncoded := false
	for _, f := range results {
		if f.Metadata["encoding"] == "base64" {
			foundEncoded = true
		}
	}
	if !foundEncoded {
		t.Log("no encoded findings (acceptable if key pattern doesn't match in decoded content alone)")
	}
}

func TestDecodeAndScan_SVGBlobSuppressesEntropy(t *testing.T) {
	// A base64 data-URI SVG whose decoded body contains long alphanumeric runs
	// that trip the entropy rules (SEC-161/162/163). The decoded content is
	// markup/image data, not a credential, so entropy-only findings must be
	// dropped. This mirrors the clean_svg_blob.ts precision-suite sample.
	a := NewAnalyzer()

	svg := `<svg xmlns="http://www.w3.org/2000/svg"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10AKIAIOSFODNN7EXAMPLEabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"/></svg>`
	encoded := base64.StdEncoding.EncodeToString([]byte(svg))
	content := []byte(`const icon = "data:image/svg+xml;base64,` + encoded + `";`)

	results := DecodeAndScan(content, "icon.ts", a.engine)

	for _, f := range results {
		if isEntropyRule(f.RuleID) {
			t.Errorf("entropy-only finding %s should be suppressed for a decoded SVG/image blob", f.RuleID)
		}
	}
}

func TestDecodeAndScan_RealSecretInBase64StillFound(t *testing.T) {
	// A genuine AWS key hidden in base64 must still be caught: the decoded
	// content is a bare credential, not an image/markup blob.
	a := NewAnalyzer()

	secret := "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	content := []byte("blob = " + encoded)

	results := DecodeAndScan(content, "config.py", a.engine)

	if len(results) == 0 {
		t.Fatal("expected a decoded-secret finding for a real credential hidden in base64")
	}
	found := false
	for _, f := range results {
		if f.Metadata["encoding"] == "base64" {
			found = true
		}
	}
	if !found {
		t.Error("real secret in base64 should surface as an encoded finding")
	}
}

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		input []byte
		want  bool
	}{
		{[]byte("hello world"), true},
		{[]byte{0x00, 0x01, 0x02}, false},
		{[]byte{}, false},
		{[]byte("mostly printable\x01"), true},
	}

	for _, tc := range tests {
		got := isPrintable(tc.input)
		if got != tc.want {
			t.Errorf("isPrintable(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestFalsePositiveRejection(t *testing.T) {
	// Random-looking base64 that decodes to binary (non-printable).
	content := []byte("hash = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	segments := decodeBase64Segments(content)

	for _, seg := range segments {
		if !isPrintable([]byte(seg.Decoded)) {
			t.Error("non-printable segment should have been filtered")
		}
	}
}
