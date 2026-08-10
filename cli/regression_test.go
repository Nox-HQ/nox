package main

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// The exact shape that produced felixgeelhaar/specular#51: nine advisories on
// golang.org/x/crypto, installed at 0.54.0, each naming the version that
// closed it. Several are below what is installed.
func TestRegressionSpecular51(t *testing.T) {
	fixes := []string{"0.51.0", "0.44.0", "0.35.0", "0.51.0", "0.31.0", "0.17.0", "0.51.0", "0.50.0", "0.49.0"}
	var items []findings.Finding
	for _, f := range fixes {
		items = append(items, findings.Finding{
			RuleID: "VULN-001",
			Metadata: map[string]string{
				"ecosystem": "go", "package": "golang.org/x/crypto",
				"version": "0.54.0", "fixed_in": f,
			},
		})
	}

	plan := planUpgrades(items, true)
	for _, a := range plan.actions {
		t.Errorf("planned a move from %s to %s — every candidate is below the installed version",
			a.fromVer, a.toVersion)
	}
	if len(plan.actions) == 0 {
		t.Logf("correctly planned nothing; %d skipped", plan.skipped)
	}
}

// felixgeelhaar/orbita#49: grpc 1.79.3 installed, advisory fixed_in a real but
// development-marker tag.
func TestRegressionOrbita49(t *testing.T) {
	items := []findings.Finding{{
		RuleID: "VULN-001",
		Metadata: map[string]string{
			"ecosystem": "go", "package": "google.golang.org/grpc",
			"version": "1.79.3", "fixed_in": "1.81.0-dev",
		},
	}}
	plan := planUpgrades(items, true)
	for _, a := range plan.actions {
		t.Errorf("planned %s -> %s; a stable install must not adopt a prerelease", a.fromVer, a.toVersion)
	}
}
