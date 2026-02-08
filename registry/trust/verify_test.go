package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func setupVerifyTest(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, []byte, *Keyring) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pemData := ExportKeyPEM(pub)

	kr := NewKeyring()
	k, err := NewKey("trusted-signer", pemData)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	kr.Add(k)

	return pub, priv, pemData, kr
}

func TestVerifyArtifactVerified(t *testing.T) {
	_, priv, pemData, kr := setupVerifyTest(t)
	v := NewVerifier(WithKeyring(kr), WithTrustPolicy(DefaultTrustPolicy()))

	content := []byte("trusted artifact content")
	digest := ComputeDigest(content).String()
	sig := ed25519.Sign(priv, content)

	result := v.VerifyArtifact(content, digest, sig, pemData, "v1")

	if !result.OK() {
		t.Errorf("expected OK, got violations: %v", result.Violations)
	}
	if result.TrustLevel != TrustVerified {
		t.Errorf("TrustLevel = %v, want %v", result.TrustLevel, TrustVerified)
	}
	if !result.DigestMatch {
		t.Error("DigestMatch should be true")
	}
	if !result.SignatureValid {
		t.Error("SignatureValid should be true")
	}
	if result.SignerName != "trusted-signer" {
		t.Errorf("SignerName = %q, want %q", result.SignerName, "trusted-signer")
	}
	if result.SignerKey == "" {
		t.Error("SignerKey should not be empty")
	}
	if result.VerifiedAt.IsZero() {
		t.Error("VerifiedAt should be set")
	}
}

func TestVerifyArtifactCommunity(t *testing.T) {
	// Use a key NOT in the keyring.
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pemData2 := ExportKeyPEM(pub2)

	// Keyring has a different key.
	_, _, _, kr := setupVerifyTest(t)
	v := NewVerifier(
		WithKeyring(kr),
		WithTrustPolicy(PermissiveTrustPolicy()),
	)

	content := []byte("community artifact")
	digest := ComputeDigest(content).String()
	sig := ed25519.Sign(priv2, content)

	result := v.VerifyArtifact(content, digest, sig, pemData2, "v1")

	if result.TrustLevel != TrustCommunity {
		t.Errorf("TrustLevel = %v, want %v", result.TrustLevel, TrustCommunity)
	}
	if !result.SignatureValid {
		t.Error("SignatureValid should be true")
	}
	if result.SignerName != "" {
		t.Errorf("SignerName = %q, want empty", result.SignerName)
	}
}

func TestVerifyArtifactUnsigned(t *testing.T) {
	v := NewVerifier(WithTrustPolicy(PermissiveTrustPolicy()))

	content := []byte("unsigned artifact")
	digest := ComputeDigest(content).String()

	result := v.VerifyArtifact(content, digest, nil, nil, "v1")

	if result.TrustLevel != TrustUnverified {
		t.Errorf("TrustLevel = %v, want %v", result.TrustLevel, TrustUnverified)
	}
	if result.SignatureValid {
		t.Error("SignatureValid should be false")
	}
	// Permissive policy: should be OK.
	if !result.OK() {
		t.Errorf("expected OK with permissive policy, got violations: %v", result.Violations)
	}
}

func TestVerifyArtifactBadDigest(t *testing.T) {
	_, priv, pemData, kr := setupVerifyTest(t)
	v := NewVerifier(WithKeyring(kr), WithTrustPolicy(DefaultTrustPolicy()))

	content := []byte("real content")
	wrongDigest := ComputeDigest([]byte("different content")).String()
	sig := ed25519.Sign(priv, content)

	result := v.VerifyArtifact(content, wrongDigest, sig, pemData, "v1")

	if result.DigestMatch {
		t.Error("DigestMatch should be false")
	}
	if result.OK() {
		t.Error("should not be OK with bad digest")
	}
}

func TestVerifyArtifactBadSignature(t *testing.T) {
	_, priv, pemData, kr := setupVerifyTest(t)
	v := NewVerifier(WithKeyring(kr), WithTrustPolicy(DefaultTrustPolicy()))

	content := []byte("content")
	digest := ComputeDigest(content).String()
	sig := ed25519.Sign(priv, []byte("different content"))

	result := v.VerifyArtifact(content, digest, sig, pemData, "v1")

	if result.SignatureValid {
		t.Error("SignatureValid should be false")
	}
	if result.TrustLevel != TrustUnverified {
		t.Errorf("TrustLevel = %v, want %v", result.TrustLevel, TrustUnverified)
	}
}

func TestVerifyArtifactIncompatibleAPIVersion(t *testing.T) {
	_, priv, pemData, kr := setupVerifyTest(t)
	v := NewVerifier(WithKeyring(kr), WithTrustPolicy(DefaultTrustPolicy()))

	content := []byte("content")
	digest := ComputeDigest(content).String()
	sig := ed25519.Sign(priv, content)

	result := v.VerifyArtifact(content, digest, sig, pemData, "v999")

	if result.OK() {
		t.Error("should not be OK with incompatible API version")
	}

	found := false
	for _, v := range result.Violations {
		if v.Field == "api_version" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected api_version violation")
	}
}

func TestVerifyArtifactBelowMinimumTrust(t *testing.T) {
	v := NewVerifier(WithTrustPolicy(EnterpriseTrustPolicy()))

	content := []byte("unsigned content")
	digest := ComputeDigest(content).String()

	result := v.VerifyArtifact(content, digest, nil, nil, "v1")

	if result.OK() {
		t.Error("should not be OK: unsigned fails enterprise policy")
	}

	found := false
	for _, v := range result.Violations {
		if v.Field == "trust_level" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected trust_level violation")
	}
}

func TestVerifyArtifactMultipleViolations(t *testing.T) {
	v := NewVerifier(WithTrustPolicy(EnterpriseTrustPolicy()))

	content := []byte("bad artifact")
	wrongDigest := ComputeDigest([]byte("different")).String()

	result := v.VerifyArtifact(content, wrongDigest, nil, nil, "v999")

	// Should have: digest mismatch, API version, trust level below minimum, digest required
	if len(result.Violations) < 3 {
		t.Errorf("expected at least 3 violations, got %d: %v", len(result.Violations), result.Violations)
	}

	fields := make(map[string]bool)
	for _, v := range result.Violations {
		fields[v.Field] = true
	}

	for _, expected := range []string{"digest", "api_version", "trust_level"} {
		if !fields[expected] {
			t.Errorf("missing expected violation field: %q", expected)
		}
	}
}

func TestVerifyArtifactNoDigestProvided(t *testing.T) {
	v := NewVerifier(WithTrustPolicy(PermissiveTrustPolicy()))

	content := []byte("content without digest")
	result := v.VerifyArtifact(content, "", nil, nil, "v1")

	// With permissive policy and no expected digest, DigestMatch stays false,
	// but RequireDigest is false so no violation.
	if result.DigestMatch {
		t.Error("DigestMatch should be false when no expected digest provided")
	}
}

func TestVerifierDefaults(t *testing.T) {
	v := NewVerifier()

	// Defaults: empty keyring, DefaultTrustPolicy.
	content := []byte("test")
	digest := ComputeDigest(content).String()

	result := v.VerifyArtifact(content, digest, nil, nil, "v1")

	// Unsigned fails default policy (requires Community).
	if result.OK() {
		t.Error("unsigned should fail default policy")
	}
}
