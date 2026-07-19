package deps

import (
	"math"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// Base scores below are the published values for these vectors, per the
// CVSS v3.1 specification (https://www.first.org/cvss/v3.1/specification-document).
func TestCVSSV3BaseScore(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   float64
	}{
		{"critical RCE", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"scope changed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"local low impact", "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8},
		{"medium, scope unchanged", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4},
		// Same vector with scope changed: exercises the 1.08 multiplier and the
		// separate impact formula, which must lift 5.4 to 6.1.
		{"medium, scope changed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"no impact scores zero", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		{"v3.0 prefix also supported", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
	}
	for _, tt := range tests {
		got, ok := cvssV3BaseScore(tt.vector)
		if !ok {
			t.Errorf("%s: vector not parsed", tt.name)
			continue
		}
		if math.Abs(got-tt.want) > 0.05 {
			t.Errorf("%s: got %.1f, want %.1f", tt.name, got, tt.want)
		}
	}
}

func TestCVSSV3BaseScore_RejectsNonVectors(t *testing.T) {
	for _, s := range []string{"", "9.8", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", "nonsense"} {
		if _, ok := cvssV3BaseScore(s); ok {
			t.Errorf("expected %q to be rejected as a v3 vector", s)
		}
	}
}

// OSV publishes CVSS as vector strings, not numeric scores. Before this was
// handled, every vector fell through to the SeverityMedium default — so a
// critical dependency CVE could never trip a high/critical gate.
func TestCVSSToSeverity_HandlesVectorStrings(t *testing.T) {
	tests := []struct {
		score string
		want  findings.Severity
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", findings.SeverityCritical},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", findings.SeverityMedium},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", findings.SeverityLow},
		{"9.8", findings.SeverityCritical}, // plain floats still work
		{"7.0", findings.SeverityHigh},
	}
	for _, tt := range tests {
		if got := cvssToSeverity(tt.score); got != tt.want {
			t.Errorf("cvssToSeverity(%q) = %v, want %v", tt.score, got, tt.want)
		}
	}
}
