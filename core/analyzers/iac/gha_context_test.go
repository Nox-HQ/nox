package iac

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestApplyGHAContext_EphemeralTestDB_DowngradesSeverity(t *testing.T) {
	t.Parallel()

	workflow := []byte(`name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: testpass
          POSTGRES_USER: testuser
    steps:
      - run: go test ./...
`)
	in := []findings.Finding{
		{
			RuleID:   "SEC-073",
			Severity: findings.SeverityCritical,
			Location: findings.Location{FilePath: ".github/workflows/ci.yml", StartLine: 8},
		},
		{
			RuleID:   "IAC-254",
			Severity: findings.SeverityCritical,
			Location: findings.Location{FilePath: ".github/workflows/ci.yml", StartLine: 9},
		},
	}

	out := ApplyGHAContext(in, map[string][]byte{
		".github/workflows/ci.yml": workflow,
	})

	for _, f := range out {
		if f.Severity != findings.SeverityInfo {
			t.Errorf("expected severity info for %s, got %s", f.RuleID, f.Severity)
		}
		if f.Metadata["gha_context"] != "ephemeral_test_db" {
			t.Errorf("expected gha_context=ephemeral_test_db for %s, got %v", f.RuleID, f.Metadata)
		}
	}
}

func TestApplyGHAContext_NoServicesBlock_LeavesSeverity(t *testing.T) {
	t.Parallel()

	workflow := []byte(`name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      DB_PASSWORD: prod-secret
    steps:
      - run: ./deploy.sh
`)
	in := []findings.Finding{{
		RuleID:   "SEC-073",
		Severity: findings.SeverityCritical,
		Location: findings.Location{FilePath: ".github/workflows/deploy.yml", StartLine: 7},
	}}

	out := ApplyGHAContext(in, map[string][]byte{
		".github/workflows/deploy.yml": workflow,
	})

	if out[0].Severity != findings.SeverityCritical {
		t.Errorf("severity should remain critical without services: block, got %s", out[0].Severity)
	}
}

func TestApplyGHAContext_ContentsWritePairedWithReleaseAction(t *testing.T) {
	t.Parallel()

	workflow := []byte(`name: release
permissions:
  contents: write
jobs:
  release:
    steps:
      - uses: goreleaser/goreleaser-action@v6
`)
	in := []findings.Finding{{
		RuleID:   "IAC-314",
		Severity: findings.SeverityMedium,
		Location: findings.Location{FilePath: ".github/workflows/release.yml", StartLine: 3},
	}}

	out := ApplyGHAContext(in, map[string][]byte{
		".github/workflows/release.yml": workflow,
	})

	if out[0].Severity != findings.SeverityLow {
		t.Errorf("contents:write paired with goreleaser should downgrade to low, got %s", out[0].Severity)
	}
	if out[0].Metadata["gha_context"] != "justified_by_consumer_action" {
		t.Errorf("expected gha_context=justified_by_consumer_action, got %v", out[0].Metadata)
	}
}

func TestApplyGHAContext_BareContentsWriteUnchanged(t *testing.T) {
	t.Parallel()

	workflow := []byte(`name: thing
permissions:
  contents: write
jobs:
  build:
    steps:
      - run: echo hi
`)
	in := []findings.Finding{{
		RuleID:   "IAC-314",
		Severity: findings.SeverityMedium,
		Location: findings.Location{FilePath: ".github/workflows/build.yml", StartLine: 3},
	}}

	out := ApplyGHAContext(in, map[string][]byte{
		".github/workflows/build.yml": workflow,
	})

	if out[0].Severity != findings.SeverityMedium {
		t.Errorf("bare contents:write must stay medium, got %s", out[0].Severity)
	}
}

func TestApplyGHAContext_OnlyAffectsWorkflowPaths(t *testing.T) {
	t.Parallel()

	in := []findings.Finding{{
		RuleID:   "SEC-073",
		Severity: findings.SeverityCritical,
		Location: findings.Location{FilePath: "config.yml", StartLine: 3},
	}}

	out := ApplyGHAContext(in, map[string][]byte{})
	if out[0].Severity != findings.SeverityCritical {
		t.Errorf("non-workflow paths must be untouched, got %s", out[0].Severity)
	}
}
