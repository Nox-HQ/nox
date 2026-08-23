package htmlreport

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestGenerateEmpty(t *testing.T) {
	t.Parallel()
	r := NewReporter("test")
	fs := findings.NewFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatal(err)
	}

	html := string(data)
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("missing DOCTYPE")
	}
	if !strings.Contains(html, "No security findings detected") {
		t.Error("expected no-findings message")
	}
	if !strings.Contains(html, "nox test") {
		t.Error("expected tool version")
	}
}

func TestGenerateWithFindings(t *testing.T) {
	t.Parallel()
	r := NewReporter("v1.0.0")
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		RuleID:     "SEC-001",
		Severity:   findings.SeverityCritical,
		Confidence: findings.ConfidenceHigh,
		Location:   findings.Location{FilePath: "main.go", StartLine: 10},
		Message:    "Hardcoded AWS key",
	})
	fs.Add(findings.Finding{
		RuleID:     "IAC-100",
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceMedium,
		Location:   findings.Location{FilePath: "deploy.tf", StartLine: 5},
		Message:    "S3 bucket without encryption",
	})

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatal(err)
	}

	html := string(data)
	if !strings.Contains(html, "SEC-001") {
		t.Error("missing SEC-001 in output")
	}
	if !strings.Contains(html, "IAC-100") {
		t.Error("missing IAC-100 in output")
	}
	if !strings.Contains(html, "main.go") {
		t.Error("missing file path")
	}
	if !strings.Contains(html, "Hardcoded AWS key") {
		t.Error("missing message")
	}
	if !strings.Contains(html, `class="badge critical"`) {
		t.Error("missing critical badge class")
	}
	if !strings.Contains(html, `class="badge medium"`) {
		t.Error("missing medium badge class")
	}
}

func TestGenerateSeverityCounts(t *testing.T) {
	t.Parallel()
	r := NewReporter("test")
	fs := findings.NewFindingSet()

	for _, sev := range []findings.Severity{
		findings.SeverityCritical,
		findings.SeverityHigh,
		findings.SeverityHigh,
		findings.SeverityMedium,
		findings.SeverityLow,
		findings.SeverityInfo,
	} {
		fs.Add(findings.Finding{
			RuleID:   "TEST-001",
			Severity: sev,
			Message:  "test " + string(sev),
			Location: findings.Location{FilePath: string(sev) + ".go"},
		})
	}

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatal(err)
	}

	html := string(data)
	// Should have the bar chart with segments.
	if !strings.Contains(html, `class="bar-chart"`) {
		t.Error("missing bar chart")
	}
}

func TestGenerateXSSSafety(t *testing.T) {
	t.Parallel()
	r := NewReporter("test")
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		RuleID:   "SEC-001",
		Severity: findings.SeverityHigh,
		Message:  `<script>alert("xss")</script>`,
		Location: findings.Location{FilePath: "evil.go"},
	})

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatal(err)
	}

	html := string(data)
	if strings.Contains(html, `<script>alert("xss")</script>`) {
		t.Error("XSS not escaped in output")
	}
}

func TestGenerateSuppressedNotIncluded(t *testing.T) {
	t.Parallel()
	r := NewReporter("test")
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		RuleID:   "SEC-001",
		Severity: findings.SeverityHigh,
		Message:  "active finding",
		Location: findings.Location{FilePath: "a.go"},
	})
	fs.Add(findings.Finding{
		RuleID:   "SEC-002",
		Severity: findings.SeverityHigh,
		Message:  "suppressed finding",
		Location: findings.Location{FilePath: "b.go"},
		Status:   findings.StatusSuppressed,
	})

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatal(err)
	}

	html := string(data)
	if !strings.Contains(html, "SEC-001") {
		t.Error("expected active finding")
	}
	if strings.Contains(html, "SEC-002") {
		t.Error("suppressed finding should not appear")
	}
}

// TestGenerateHonorsSourceDateEpoch guards nox's reproducible-output guarantee
// for the HTML artifact (DEFECT 3): the embedded timestamp must come from
// report.GeneratedAt(), which honors SOURCE_DATE_EPOCH like the JSON and SBOM
// emitters, not wall-clock time.Now(). Without this the HTML report is never
// byte-reproducible across runs.
func TestGenerateHonorsSourceDateEpoch(t *testing.T) {
	// t.Setenv is incompatible with t.Parallel.
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")

	r := NewReporter("test")
	fs := findings.NewFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatal(err)
	}

	// 1700000000 == 2023-11-14T22:13:20Z.
	const frozen = "2023-11-14T22:13:20Z"
	html := string(data)
	if !strings.Contains(html, frozen) {
		t.Errorf("HTML report does not embed frozen SOURCE_DATE_EPOCH timestamp %q", frozen)
	}
}

func TestWriteToFile(t *testing.T) {
	t.Parallel()
	r := NewReporter("test")
	fs := findings.NewFindingSet()

	path := t.TempDir() + "/report.html"
	if err := r.WriteToFile(fs, path); err != nil {
		t.Fatal(err)
	}
}

func TestSevRank(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  int
	}{
		{"critical", 0},
		{"high", 1},
		{"medium", 2},
		{"low", 3},
		{"info", 4},
		// An unrecognised severity now ranks past info (via findings.SeverityRank),
		// so it sorts last instead of tying with info.
		{"unknown", 5},
	}
	for _, tt := range tests {
		got := sevRank(tt.input)
		if got != tt.want {
			t.Errorf("sevRank(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestSevClass(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input findings.Severity
		want  string
	}{
		{findings.SeverityCritical, "critical"},
		{findings.SeverityHigh, "high"},
		{findings.SeverityMedium, "medium"},
		{findings.SeverityLow, "low"},
		{findings.SeverityInfo, "info"},
	}
	for _, tt := range tests {
		got := sevClass(tt.input)
		if got != tt.want {
			t.Errorf("sevClass(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
