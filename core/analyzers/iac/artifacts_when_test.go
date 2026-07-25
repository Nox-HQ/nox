package iac

import (
	"strings"
	"testing"
)

// IAC-348 matches `when: always` with a bare pattern, but its description and
// remediation are about JOB EXECUTION — "CI job runs regardless of previous
// failures", "running deployment jobs after test failures can push broken code
// to production".
//
// Under `artifacts:` the same two words mean something else entirely: upload
// the artifacts even when the job failed. For a scanner that is not a
// misconfiguration, it is the point — you want the SARIF and findings.json
// precisely on the run where the gate failed. nox's own GitLab example was
// flagged for doing the right thing.
//
// Same class as IAC-193 firing on `shell: bash` in a composite action: a
// pattern matching where it cannot mean what the rule assumes. Dropped rather
// than downgraded, for the same reason — a lower-severity finding still puts a
// rule in front of an operator that could never apply here.
func TestIAC348_NotReportedUnderArtifacts(t *testing.T) {
	gitlab := `nox-scan:
  script:
    - nox scan .
  artifacts:
    when: always
    paths:
      - nox-out/results.sarif
    expire_in: 1 week
`
	a := NewAnalyzer()
	got, err := a.ScanFile(".gitlab-ci.yml", []byte(gitlab))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range got {
		if f.RuleID == "IAC-348" {
			t.Errorf("IAC-348 fired on artifacts.when: always (line %d) — that means "+
				"'upload artifacts even on failure', not 'run the job regardless of failures'",
				f.Location.StartLine)
		}
	}
}

// The converse, and the reason this is a targeted drop: a job-level
// `when: always` is exactly what the rule is for and must still fire.
func TestIAC348_StillReportedOnJobLevelWhen(t *testing.T) {
	gitlab := `deploy:
  stage: deploy
  when: always
  script:
    - ./deploy.sh production
`
	a := NewAnalyzer()
	got, err := a.ScanFile(".gitlab-ci.yml", []byte(gitlab))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var found bool
	for _, f := range got {
		if f.RuleID == "IAC-348" {
			found = true
		}
	}
	if !found {
		t.Error("IAC-348 did not fire on a job-level `when: always` — a deploy job that runs " +
			"after test failures is the case this rule exists for")
	}
}

// A file mixing both: the artifacts one is dropped, the job one survives. This
// is what stops the fix from becoming "ignore when: always in gitlab files".
func TestIAC348_DistinguishesWithinOneFile(t *testing.T) {
	gitlab := `test:
  script:
    - go test ./...
  artifacts:
    when: always
    paths:
      - report.xml

deploy:
  when: always
  script:
    - ./deploy.sh
`
	a := NewAnalyzer()
	got, err := a.ScanFile(".gitlab-ci.yml", []byte(gitlab))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var lines []int
	for _, f := range got {
		if f.RuleID == "IAC-348" {
			lines = append(lines, f.Location.StartLine)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("expected exactly one IAC-348 (the deploy job), got %d at lines %v", len(lines), lines)
	}
	// The surviving one must be the job-level directive, not the artifacts one.
	body := strings.Split(gitlab, "\n")
	if l := lines[0]; l < 1 || l > len(body) || !strings.Contains(body[l-1], "when: always") {
		t.Fatalf("finding at line %d is not a when: always line", lines[0])
	}
	if lines[0] < 9 {
		t.Errorf("the surviving IAC-348 is at line %d, which is the artifacts block; "+
			"the deploy job's directive is the one that should remain", lines[0])
	}
}
