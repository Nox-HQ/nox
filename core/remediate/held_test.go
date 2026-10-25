package remediate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// A transitive fix is only "safe to apply" when the lockfile shows every
// package that needs the dependency allows the fixed version. These fixtures
// are the shapes npm writes: express 4.21.2 pins its children exactly, stripe
// asks for qs with a caret.
const heldLock = `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"express":"4.21.2","stripe":"17.4.0"}},
"node_modules/express":{"version":"4.21.2","dependencies":{"body-parser":"1.20.3","qs":"6.13.0","path-to-regexp":"0.1.12"}},
"node_modules/body-parser":{"version":"1.20.3","dependencies":{"qs":"6.13.0"}},
"node_modules/stripe":{"version":"17.4.0","dependencies":{"qs":"^6.11.0"}},
"node_modules/qs":{"version":"6.13.0"},
"node_modules/path-to-regexp":{"version":"0.1.12"}}}`

func planFor(t *testing.T, files map[string]string, ff ...findings.Finding) Plan {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Build(Input{Findings: ff, Root: root})
}

func onlyItem(t *testing.T, p Plan) Item {
	t.Helper()
	if len(p.Items) != 1 {
		t.Fatalf("items = %d, want 1: %+v", len(p.Items), p.Items)
	}
	return p.Items[0]
}

const appManifest = `{"dependencies":{"express":"4.21.2","stripe":"17.4.0"}}`

func TestPinnedTransitiveIsHeldAndNamesItsParentsAndTheEntry(t *testing.T) {
	it := onlyItem(t, planFor(t, map[string]string{"package.json": appManifest, "package-lock.json": heldLock},
		dep("qs", "6.13.0", "6.16.0", "GHSA-qs-1", "fp-qs", findings.SeverityMedium)))
	if it.Class != ClassReview || it.Kind != KindHeldUpgrade {
		t.Fatalf("got %s/%s, want needs_review/held_upgrade", it.Class, it.Kind)
	}
	for _, want := range []string{"express@4.21.2 requires qs 6.13.0", "body-parser@1.20.3 requires qs 6.13.0", `"overrides": { "qs": "6.16.0" }`} {
		if !strings.Contains(it.Why, want) {
			t.Errorf("why = %q, want %q", it.Why, want)
		}
	}
	// stripe's ^6.11.0 admits the fix and must not be blamed.
	if strings.Contains(it.Why, "stripe") {
		t.Errorf("stripe allows qs 6.16.0 but is named as a holder: %q", it.Why)
	}
	if it.Command != "" {
		t.Errorf("a held item offers no apply command, got %q", it.Command)
	}
}

func TestTransitiveWithinEveryParentRangeStaysSafe(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"stripe":"17.4.0","cookie-parser":"1.4.7"}},
"node_modules/stripe":{"version":"17.4.0","dependencies":{"qs":"^6.11.0"}},
"node_modules/cookie-parser":{"version":"1.4.7","dependencies":{"qs":"~6.13.0 || ^6.14.0"}},
"node_modules/qs":{"version":"6.13.0"}}}`
	it := onlyItem(t, planFor(t, map[string]string{"package.json": `{"dependencies":{"stripe":"17.4.0","cookie-parser":"1.4.7"}}`, "package-lock.json": lock},
		dep("qs", "6.13.0", "6.16.0", "GHSA-qs-1", "fp-qs", findings.SeverityMedium)))
	if it.Class != ClassSafe || it.Kind != KindUpgrade {
		t.Fatalf("got %s/%s, want safe_to_apply/upgrade; why=%s", it.Class, it.Kind, it.Why)
	}
}

func TestOnlyTheCopyThatIsBelowTheFixCounts(t *testing.T) {
	// A nested copy held by its parent matters; a top-level copy already past
	// the fix does not.
	lock := `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"a":"1.0.0"}},
"node_modules/a":{"version":"1.0.0","dependencies":{"qs":"6.9.0"}},
"node_modules/a/node_modules/qs":{"version":"6.9.0"},
"node_modules/qs":{"version":"6.16.0"}}}`
	it := onlyItem(t, planFor(t, map[string]string{"package.json": `{"dependencies":{"a":"1.0.0"}}`, "package-lock.json": lock},
		dep("qs", "6.9.0", "6.16.0", "GHSA-qs-1", "fp-qs", findings.SeverityMedium)))
	if it.Kind != KindHeldUpgrade || !strings.Contains(it.Why, "a@1.0.0 requires qs 6.9.0") {
		t.Fatalf("nested copy not attributed to its parent: %s/%s %s", it.Class, it.Kind, it.Why)
	}
}

func TestExistingOverridePinningLowerHoldsTheFix(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"stripe":"17.4.0"}},
"node_modules/stripe":{"version":"17.4.0","dependencies":{"qs":"^6.11.0"}},
"node_modules/qs":{"version":"6.13.0"}}}`
	manifest := `{"dependencies":{"stripe":"17.4.0"},"overrides":{"qs":"6.13.0"}}`
	it := onlyItem(t, planFor(t, map[string]string{"package.json": manifest, "package-lock.json": lock},
		dep("qs", "6.13.0", "6.16.0", "GHSA-qs-1", "fp-qs", findings.SeverityMedium)))
	if it.Kind != KindHeldUpgrade || !strings.Contains(it.Why, "package.json overrides requires qs 6.13.0") {
		t.Fatalf("an overrides entry pinning the package lower was not reported: %s/%s %s", it.Class, it.Kind, it.Why)
	}
}

func TestTransitiveWithoutAReadableNPMLockfileIsNotPromised(t *testing.T) {
	cases := map[string]map[string]string{
		"no lockfile": {"package.json": appManifest},
		"pnpm":        {"package.json": appManifest, "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"},
		"yarn":        {"package.json": appManifest, "yarn.lock": "# yarn lockfile v1\n"},
	}
	entry := map[string]string{
		"no lockfile": `"overrides": { "qs": "6.16.0" }`,
		"pnpm":        `"pnpm": { "overrides": { "qs": "6.16.0" } }`,
		"yarn":        `"resolutions": { "qs": "6.16.0" }`,
	}
	for name, files := range cases {
		it := onlyItem(t, planFor(t, files, dep("qs", "6.13.0", "6.16.0", "GHSA-qs-1", "fp-qs", findings.SeverityMedium)))
		if it.Class != ClassReview || it.Kind != KindHeldUpgrade {
			t.Errorf("%s: got %s/%s, want needs_review/held_upgrade", name, it.Class, it.Kind)
		}
		if !strings.Contains(it.Why, entry[name]) {
			t.Errorf("%s: why = %q, want the entry %s", name, it.Why, entry[name])
		}
	}
}

func TestNPMRanges(t *testing.T) {
	v := func(s string) npmVersion { x, _ := parseNPMVersion(s); return x }
	cases := []struct {
		version, rng string
		in, known    bool
	}{
		{"6.16.0", "^6.11.0", true, true},
		{"6.16.0", "6.13.0", false, true},
		{"6.16.0", "~6.13.0", false, true},
		{"6.13.5", "~6.13.0", true, true},
		{"7.0.0", "^6.11.0", false, true},
		{"0.2.5", "^0.2.0", true, true},
		{"0.3.0", "^0.2.0", false, true},
		{"1.20.9", "1.x", true, true},
		{"1.20.9", "*", true, true},
		{"1.20.9", ">=1.20.0 <1.20.5", false, true},
		{"1.20.9", ">=1.20.0 <2", true, true},
		{"1.20.9", "1.0.0 - 1.20.5", false, true},
		{"1.20.9", "<1.0.0 || ^1.20.0", true, true},
		{"1.20.9", "latest", false, false},
		{"1.20.9", "git+https://example.com/x.git", false, false},
		{"1.20.9", "^1.0.0-beta.1", false, false},
	}
	for _, c := range cases {
		in, known := satisfiesNPMRange(v(c.version), c.rng)
		if in != c.in || known != c.known {
			t.Errorf("%s in %q = (%v,%v), want (%v,%v)", c.version, c.rng, in, known, c.in, c.known)
		}
	}
}
