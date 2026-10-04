package refs

import (
	"math/rand"
	"testing"
)

// Every generated valid instance must satisfy its own reference, and every
// spec example quoted from a source must too. A reference that rejects its
// own source's example is wrong before it judges anything.
func TestValidInstancesSatisfyTheirReference(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for _, f := range Modelled {
		for _, v := range f.Valid(r) {
			if why := f.Check(v.S); why != "" {
				t.Errorf("%s/%s violates its own reference: %s\n%s", f.Name, v.Name, why, v.S)
			}
		}
	}
}

func TestSourceExamples(t *testing.T) {
	cases := []struct {
		f  *Format
		in string
	}{
		// age.md's own example identity.
		{&Age, "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"},
		// age.md's ML-KEM768-X25519 hybrid identity example.
		{&Age, "AGE-SECRET-KEY-PQ-1XX76JRALNLXDMEW0CRK45QMCCH4X06SE84UN3VPM33W6HWDX0H3SK3ZQFR"},
		// API_CreateTopic.html's example ARN.
		{&SNSTopicARN, "arn:aws:sns:us-east-2:123456789012:My-Topic"},
		// RFC 7519 §3.1's example JWT.
		{&JWT, "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		// IAM docs' example access key ID.
		{&AWSAccessKeyID, "AKIAIOSFODNN7EXAMPLE"},
	}
	for _, c := range cases {
		if why := c.f.Check(c.in); why != "" {
			t.Errorf("%s rejects its source's example %q: %s", c.f.Name, c.in, why)
		}
	}
	// RFC 7519 §6.1's unsecured JWT is a JWT and not a credential.
	if why := JWT.Check("eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."); why != "unsecured" {
		t.Errorf("RFC 7519 §6.1 example: got %q, want unsecured", why)
	}
}
