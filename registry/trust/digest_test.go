package trust

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseDigest(t *testing.T) {
	// Compute a known digest for test data.
	h := sha256.Sum256([]byte("hello"))
	validHex := hex.EncodeToString(h[:])

	tests := []struct {
		name    string
		input   string
		wantAlg string
		wantHex string
		wantErr bool
	}{
		{
			name:    "valid sha256",
			input:   "sha256:" + validHex,
			wantAlg: "sha256",
			wantHex: validHex,
		},
		{
			name:    "missing algorithm",
			input:   validHex,
			wantErr: true,
		},
		{
			name:    "unsupported algorithm",
			input:   "md5:" + strings.Repeat("ab", 16),
			wantErr: true,
		},
		{
			name:    "wrong hex length",
			input:   "sha256:abcdef",
			wantErr: true,
		},
		{
			name:    "invalid hex chars",
			input:   "sha256:" + strings.Repeat("zz", 32),
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "uppercase hex normalized",
			input:   "sha256:" + strings.ToUpper(validHex),
			wantAlg: "sha256",
			wantHex: validHex,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := ParseDigest(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseDigest(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if d.Algorithm != tt.wantAlg {
				t.Errorf("Algorithm = %q, want %q", d.Algorithm, tt.wantAlg)
			}
			if d.Hex != tt.wantHex {
				t.Errorf("Hex = %q, want %q", d.Hex, tt.wantHex)
			}
		})
	}
}

func TestDigestString(t *testing.T) {
	d := Digest{Algorithm: "sha256", Hex: "abcdef"}
	if got := d.String(); got != "sha256:abcdef" {
		t.Errorf("String() = %q, want %q", got, "sha256:abcdef")
	}
}

func TestComputeDigest(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"hello", []byte("hello")},
		{"binary", []byte{0x00, 0x01, 0x02, 0xff}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := ComputeDigest(tt.data)
			if d.Algorithm != "sha256" {
				t.Errorf("Algorithm = %q, want sha256", d.Algorithm)
			}
			expected := sha256.Sum256(tt.data)
			expectedHex := hex.EncodeToString(expected[:])
			if d.Hex != expectedHex {
				t.Errorf("Hex = %q, want %q", d.Hex, expectedHex)
			}
		})
	}
}

func TestComputeDigestReader(t *testing.T) {
	data := []byte("streaming test data")
	d, err := ComputeDigestReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ComputeDigestReader() error = %v", err)
	}

	expected := ComputeDigest(data)
	if d.Hex != expected.Hex {
		t.Errorf("streaming digest %q != in-memory digest %q", d.Hex, expected.Hex)
	}
}

func TestVerifyDigest(t *testing.T) {
	data := []byte("test content")
	d := ComputeDigest(data)

	tests := []struct {
		name     string
		data     []byte
		expected string
		want     bool
		wantErr  bool
	}{
		{
			name:     "matching digest",
			data:     data,
			expected: d.String(),
			want:     true,
		},
		{
			name:     "mismatched digest",
			data:     []byte("different content"),
			expected: d.String(),
			want:     false,
		},
		{
			name:     "invalid expected format",
			data:     data,
			expected: "not-a-digest",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyDigest(tt.data, tt.expected)
			if (err != nil) != tt.wantErr {
				t.Fatalf("VerifyDigest() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("VerifyDigest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestComputeDigestDeterministic(t *testing.T) {
	data := []byte("determinism test")
	d1 := ComputeDigest(data)
	d2 := ComputeDigest(data)
	if d1.Hex != d2.Hex {
		t.Errorf("non-deterministic: %q != %q", d1.Hex, d2.Hex)
	}
}
