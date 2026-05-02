package trust

import "time"

// Verifier orchestrates artifact verification: digest checking, signature
// validation, trust classification, and policy enforcement.
type Verifier struct {
	keyring *Keyring
	policy  Policy
}

// VerifierOption is a functional option for configuring a Verifier.
type VerifierOption func(*Verifier)

// WithKeyring sets the keyring for signature verification.
func WithKeyring(kr *Keyring) VerifierOption {
	return func(v *Verifier) { v.keyring = kr }
}

// WithPolicy sets the trust policy for enforcement.
func WithPolicy(p Policy) VerifierOption {
	return func(v *Verifier) { v.policy = p }
}

// Policy returns the verifier's configured policy. Used by callers
// that promote a verification result out-of-band (e.g. an OCI store
// passing a Cosign keyless verification) and then need to re-enforce
// the policy against the updated trust level.
func (v *Verifier) Policy() Policy { return v.policy }

// NewVerifier creates a Verifier with the given options.
// Defaults: empty keyring, DefaultPolicy().
func NewVerifier(opts ...VerifierOption) *Verifier {
	v := &Verifier{
		keyring: NewKeyring(),
		policy:  DefaultPolicy(),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// VerifyArtifact performs full artifact verification:
//  1. Verify content digest matches expected
//  2. If signature provided, verify Ed25519 signature
//  3. Classify trust level based on signature and keyring
//  4. Check API version compatibility
//  5. Enforce minimum trust level
//  6. Return result with all violations collected
func (v *Verifier) VerifyArtifact(
	content []byte,
	expectedDigest string,
	signature []byte,
	signerKeyPEM []byte,
	apiVersion string,
) VerifyResult {
	result := VerifyResult{
		Level:      TrustUnverified,
		VerifiedAt: time.Now(),
	}

	// Step 1: Digest verification.
	if expectedDigest != "" {
		match, err := VerifyDigest(content, expectedDigest)
		if err != nil {
			result.Violations = append(result.Violations, Violation{
				Field:   "digest",
				Message: err.Error(),
			})
		} else {
			result.DigestMatch = match
			if !match {
				result.Violations = append(result.Violations, Violation{
					Field:   "digest",
					Message: "content digest does not match expected digest",
				})
			}
		}
	}

	// Step 2: Signature verification.
	if len(signature) > 0 && len(signerKeyPEM) > 0 {
		valid, err := VerifySignature(content, signature, signerKeyPEM)
		if err != nil {
			result.Violations = append(result.Violations, Violation{
				Field:   "signature",
				Message: err.Error(),
			})
		} else {
			result.SignatureValid = valid
			if !valid {
				result.Violations = append(result.Violations, Violation{
					Field:   "signature",
					Message: "signature verification failed",
				})
			}
		}

		// Step 3: Trust classification.
		if result.SignatureValid {
			pub, err := ParsePublicKey(signerKeyPEM)
			if err == nil {
				fp := KeyFingerprint(pub)
				result.SignerKey = fp

				if key := v.keyring.Find(fp); key != nil {
					result.Level = TrustVerified
					result.SignerName = key.Name
				} else {
					result.Level = TrustCommunity
				}
			}
		}
	}

	// Step 4: API version check.
	if apiVersion != "" {
		result.Violations = append(result.Violations, v.policy.CheckAPIVersion(apiVersion)...)
	}

	// Step 5: Policy enforcement.
	result.Violations = append(result.Violations, v.policy.Enforce(&result)...)

	return result
}
