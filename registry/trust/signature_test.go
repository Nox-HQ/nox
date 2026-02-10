package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"
)

func generateTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	return pub, priv
}

func rawPEM(pub ed25519.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: []byte(pub),
	})
}

func pkixPEM(pub ed25519.PublicKey) []byte {
	der := append(append([]byte{}, ed25519PKIXPrefix...), []byte(pub)...)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
}

func TestVerifySignature(t *testing.T) {
	pub, priv := generateTestKey(t)
	content := []byte("artifact content")
	sig := ed25519.Sign(priv, content)
	pubPEM := rawPEM(pub)

	tests := []struct {
		name    string
		content []byte
		sig     []byte
		keyPEM  []byte
		want    bool
		wantErr bool
	}{
		{
			name:    "valid signature",
			content: content,
			sig:     sig,
			keyPEM:  pubPEM,
			want:    true,
		},
		{
			name:    "tampered content",
			content: []byte("tampered content"),
			sig:     sig,
			keyPEM:  pubPEM,
			want:    false,
		},
		{
			name:    "wrong key",
			content: content,
			sig:     sig,
			keyPEM: func() []byte {
				pub2, _ := generateTestKey(t)
				return rawPEM(pub2)
			}(),
			want: false,
		},
		{
			name:    "tampered signature",
			content: content,
			sig: func() []byte {
				tampered := make([]byte, len(sig))
				copy(tampered, sig)
				tampered[0] ^= 0xff
				return tampered
			}(),
			keyPEM: pubPEM,
			want:   false,
		},
		{
			name:    "invalid signature length",
			content: content,
			sig:     []byte("short"),
			keyPEM:  pubPEM,
			wantErr: true,
		},
		{
			name:    "invalid PEM",
			content: content,
			sig:     sig,
			keyPEM:  []byte("not a pem block"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifySignature(tt.content, tt.sig, tt.keyPEM)
			if (err != nil) != tt.wantErr {
				t.Fatalf("VerifySignature() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("VerifySignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePublicKeyRawPEM(t *testing.T) {
	pub, _ := generateTestKey(t)
	pemData := rawPEM(pub)

	parsed, err := ParsePublicKey(pemData)
	if err != nil {
		t.Fatalf("ParsePublicKey(raw PEM) error = %v", err)
	}
	if !pub.Equal(parsed) {
		t.Error("parsed key does not match original")
	}
}

func TestParsePublicKeyPKIXPEM(t *testing.T) {
	pub, _ := generateTestKey(t)
	pemData := pkixPEM(pub)

	parsed, err := ParsePublicKey(pemData)
	if err != nil {
		t.Fatalf("ParsePublicKey(PKIX PEM) error = %v", err)
	}
	if !pub.Equal(parsed) {
		t.Error("parsed key does not match original")
	}
}

func TestParsePublicKeyErrors(t *testing.T) {
	tests := []struct {
		name    string
		pemData []byte
	}{
		{
			name:    "no PEM block",
			pemData: []byte("not a pem block"),
		},
		{
			name: "wrong PEM type",
			pemData: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: make([]byte, 32),
			}),
		},
		{
			name: "raw PEM wrong size",
			pemData: pem.EncodeToMemory(&pem.Block{
				Type:  "ED25519 PUBLIC KEY",
				Bytes: make([]byte, 16),
			}),
		},
		{
			name: "PKIX PEM wrong size",
			pemData: pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: make([]byte, 16),
			}),
		},
		{
			name: "PKIX PEM invalid prefix",
			pemData: pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: make([]byte, len(ed25519PKIXPrefix)+ed25519.PublicKeySize),
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePublicKey(tt.pemData)
			if err == nil {
				t.Error("ParsePublicKey() expected error, got nil")
			}
		})
	}
}

func TestSignVerifyWithPKIXKey(t *testing.T) {
	pub, priv := generateTestKey(t)
	content := []byte("test with PKIX key")
	sig := ed25519.Sign(priv, content)

	valid, err := VerifySignature(content, sig, pkixPEM(pub))
	if err != nil {
		t.Fatalf("VerifySignature(PKIX) error = %v", err)
	}
	if !valid {
		t.Error("VerifySignature(PKIX) = false, want true")
	}
}
