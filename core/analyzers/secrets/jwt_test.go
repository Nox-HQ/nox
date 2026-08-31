package secrets

import "testing"

// TestVerifyJWTAgainstAKnownToken licenses the JWT check the way the checksum
// test licenses the checksum: against a real, published token, not one the test
// generated.
//
// This is the standard HS256 example from RFC 7519 / jwt.io. It is not a
// credential — the signing key "your-256-bit-secret" is public — but its
// structure is a genuine JWT, so it is the right thing to verify the decoder
// against. A decoder checked only against tokens it built itself would prove
// its encoder and decoder agree, which is circular.
func TestVerifyJWTAgainstAKnownToken(t *testing.T) {
	const known = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	consistent, applicable := verifyJWT(known)
	if !applicable {
		t.Fatal("a real JWT was not recognised as checkable")
	}
	if !consistent {
		t.Error("a real JWT did not verify; the decoder is wrong")
	}

	// The same token behind a Bearer prefix, as a header carries it.
	if c, a := verifyJWT("Bearer " + known); !a || !c {
		t.Errorf("a bearer-prefixed JWT was not verified: consistent=%v applicable=%v", c, a)
	}
}

// TestAJWTLookalikeIsRefutedNotIgnored is the value of the check.
//
// A string matching the loose eyJ....eyJ.... pattern whose header is not valid
// base64url JSON is deterministically not a JWT. Refuting it is the deterministic
// claim; staying silent would leave the finding resting on the pattern alone.
func TestAJWTLookalikeIsRefutedNotIgnored(t *testing.T) {
	// Three dot-separated segments, first starts with eyJ, but the header is
	// not decodable JSON.
	consistent, applicable := verifyJWT("eyJnotvalidbase64json.eyJalsonot.signature")
	if !applicable {
		t.Error("a JWT-shaped string was treated as uncheckable rather than refuted")
	}
	if consistent {
		t.Error("a string that is not a JWT verified as one")
	}

	// A JSON header with no algorithm is not a JWT header.
	// base64url of {"typ":"JWT"} — valid JSON, no alg.
	noAlg := "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ4In0.sig"
	if c, a := verifyJWT(noAlg); !a || c {
		t.Errorf("a header with no algorithm verified as a JWT: consistent=%v", c)
	}
}

// TestVerifyJWTIsThreeValued. A value that is not JWT-shaped must produce
// applicable=false — "I cannot check this" is not "I checked and it failed", the
// same discipline the checksum keeps.
func TestVerifyJWTIsThreeValued(t *testing.T) {
	for _, notAJWT := range []string{
		"", "ghp_016C7f8e9d0A1b2C3d4E5f6G7h8I9j0K1l2M",
		"just-a-string", "two.parts", "AKIAIOSFODNN7EXAMPLE",
	} {
		if _, applicable := verifyJWT(notAJWT); applicable {
			t.Errorf("verifyJWT(%q) claimed to be able to check a non-JWT", notAJWT)
		}
	}
}
