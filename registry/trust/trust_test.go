package trust

import (
	"testing"
	"time"
)

func TestTrustLevelString(t *testing.T) {
	tests := []struct {
		level TrustLevel
		want  string
	}{
		{TrustUnverified, "unverified"},
		{TrustCommunity, "community"},
		{TrustVerified, "verified"},
		{TrustLevel(99), "TrustLevel(99)"},
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("TrustLevel(%d).String() = %q, want %q", int(tt.level), got, tt.want)
		}
	}
}

func TestParseTrustLevel(t *testing.T) {
	tests := []struct {
		input   string
		want    TrustLevel
		wantErr bool
	}{
		{"unverified", TrustUnverified, false},
		{"community", TrustCommunity, false},
		{"verified", TrustVerified, false},
		{"VERIFIED", TrustVerified, false},
		{"Community", TrustCommunity, false},
		{"unknown", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseTrustLevel(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseTrustLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("ParseTrustLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestTrustLevelStringRoundTrip(t *testing.T) {
	for _, level := range []TrustLevel{TrustUnverified, TrustCommunity, TrustVerified} {
		parsed, err := ParseTrustLevel(level.String())
		if err != nil {
			t.Fatalf("ParseTrustLevel(%q) failed: %v", level.String(), err)
		}
		if parsed != level {
			t.Errorf("round-trip failed: %v → %q → %v", level, level.String(), parsed)
		}
	}
}

func TestTrustLevelOrdering(t *testing.T) {
	if TrustUnverified >= TrustCommunity {
		t.Error("TrustUnverified should be less than TrustCommunity")
	}
	if TrustCommunity >= TrustVerified {
		t.Error("TrustCommunity should be less than TrustVerified")
	}
}

func TestTrustViolationError(t *testing.T) {
	v := TrustViolation{Field: "digest", Message: "mismatch"}
	want := "trust violation on digest: mismatch"
	if got := v.Error(); got != want {
		t.Errorf("TrustViolation.Error() = %q, want %q", got, want)
	}
}

func TestVerifyResultOK(t *testing.T) {
	tests := []struct {
		name   string
		result VerifyResult
		want   bool
	}{
		{
			name:   "ok: digest matches, no violations",
			result: VerifyResult{DigestMatch: true},
			want:   true,
		},
		{
			name:   "not ok: digest mismatch",
			result: VerifyResult{DigestMatch: false},
			want:   false,
		},
		{
			name: "not ok: violations present",
			result: VerifyResult{
				DigestMatch: true,
				Violations:  []TrustViolation{{Field: "test", Message: "fail"}},
			},
			want: false,
		},
		{
			name: "not ok: both digest mismatch and violations",
			result: VerifyResult{
				DigestMatch: false,
				Violations:  []TrustViolation{{Field: "test", Message: "fail"}},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.OK(); got != tt.want {
				t.Errorf("VerifyResult.OK() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyResultVerifiedAt(t *testing.T) {
	before := time.Now()
	r := VerifyResult{VerifiedAt: time.Now()}
	if r.VerifiedAt.Before(before) {
		t.Error("VerifiedAt should not be before creation time")
	}
}
