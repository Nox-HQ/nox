package remediate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

type stubRegistry map[string]map[string]map[string]string

func (s stubRegistry) Releases(_ context.Context, pkg string) (map[string]map[string]string, error) {
	r, ok := s[pkg]
	if !ok {
		return nil, errors.New("HTTP 404 for " + pkg)
	}
	return r, nil
}

// express's own release history, as far as these packages go: 4.22.1 lets
// express's qs move but not body-parser's.
var expressHistory = stubRegistry{
	"express": {
		"4.21.2": {"body-parser": "1.20.3", "qs": "6.13.0", "path-to-regexp": "0.1.12"},
		"4.22.1": {"body-parser": "~1.20.3", "qs": "~6.16.0", "path-to-regexp": "~0.1.13"},
		"4.22.3": {"body-parser": "~1.20.5", "qs": "~6.16.0", "path-to-regexp": "~0.1.13"},
	},
	"body-parser":    {"1.20.3": {"qs": "6.13.0"}, "1.20.9": {"qs": "~6.16.0"}},
	"qs":             {"6.13.0": {}, "6.16.0": {}},
	"path-to-regexp": {"0.1.12": {}, "0.1.13": {}},
}

func planWith(t *testing.T, reg stubRegistry, ff ...findings.Finding) Plan {
	t.Helper()
	root := t.TempDir()
	for name, body := range map[string]string{"package.json": appManifest, "package-lock.json": heldLock} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	in := Input{Findings: ff, Root: root}
	if reg != nil {
		in.Registry = reg
	}
	return Build(in)
}

func TestHeldUpgradesNameTheOneParentReleaseThatFreesThem(t *testing.T) {
	p := planWith(t, expressHistory,
		dep("qs", "6.13.0", "6.16.0", "GHSA-qs-1", "fp-qs", findings.SeverityMedium),
		dep("path-to-regexp", "0.1.12", "0.1.13", "GHSA-ptr-1", "fp-ptr", findings.SeverityHigh))
	if len(p.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(p.Items))
	}
	for _, it := range p.Items {
		if it.Kind != KindHeldUpgrade {
			t.Fatalf("%s: kind %s, want held_upgrade", it.Upgrade.Package, it.Kind)
		}
		if len(it.ParentUpgrades) != 1 || it.ParentUpgrades[0].To != "4.22.3" {
			t.Fatalf("%s: parent upgrades = %+v, want express 4.22.3", it.Upgrade.Package, it.ParentUpgrades)
		}
		for _, want := range []string{"Upgrade express 4.21.2 -> 4.22.3", "express@4.22.3", `"overrides": {`} {
			if !strings.Contains(it.Why, want) {
				t.Errorf("%s: why = %q, want %q", it.Upgrade.Package, it.Why, want)
			}
		}
		if strings.Contains(it.Why, "cannot move it") || !strings.Contains(it.Why, "nox fix apply --include-review makes the upgrade") {
			t.Errorf("%s: why does not say apply makes the parent upgrade: %q", it.Upgrade.Package, it.Why)
		}
		if strings.Contains(it.Why, "Either upgrade") {
			t.Errorf("%s: the generic remedy stayed beside the named one: %q", it.Upgrade.Package, it.Why)
		}
		// stripe loads the same qs with ^6.11.0 and is not what holds it.
		if strings.Contains(it.Why, "stripe") {
			t.Errorf("%s: stripe named: %q", it.Upgrade.Package, it.Why)
		}
		if it.Command != "" {
			t.Errorf("%s: a held item still offers no apply command, got %q", it.Upgrade.Package, it.Command)
		}
	}
	if !strings.Contains(p.Items[0].Why+p.Items[1].Why, "it also frees") {
		t.Error("neither item says the one upgrade frees the other package too")
	}
}

func TestNoRegistryKeepsThePlanAsItWas(t *testing.T) {
	qs := dep("qs", "6.13.0", "6.16.0", "GHSA-qs-1", "fp-qs", findings.SeverityMedium)
	it := onlyItem(t, planWith(t, nil, qs))
	if len(it.ParentUpgrades) != 0 || !strings.Contains(it.Why, "Either upgrade") {
		t.Fatalf("an offline plan changed: %+v", it)
	}
	// A registry that cannot answer says so; it does not claim no release exists.
	it = onlyItem(t, planWith(t, stubRegistry{}, qs))
	if !strings.Contains(it.Why, "could not read express's releases") || strings.Contains(it.Why, "No published release") {
		t.Fatalf("why = %q", it.Why)
	}
}
