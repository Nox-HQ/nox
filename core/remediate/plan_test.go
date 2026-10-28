package remediate

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

var update = flag.Bool("update", false, "rewrite the golden files from the current output")

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden %s (run with -update): %v", path, err)
	}
	if string(want) != got {
		t.Errorf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func dep(pkg, version, fixed, vulnID, fp string, sev findings.Severity) findings.Finding {
	return findings.Finding{
		RuleID: "VULN-001", Severity: sev, Confidence: findings.ConfidenceHigh,
		Location:    findings.Location{FilePath: "package-lock.json", StartLine: 1},
		Message:     "Known vulnerability " + vulnID + " in " + pkg + "@" + version,
		Fingerprint: fp,
		Metadata: map[string]string{
			"ecosystem": "npm", "package": pkg, "version": version, "fixed_in": fixed, "vuln_id": vulnID,
		},
	}
}

func mavenDep(fixed, fp string) findings.Finding {
	f := dep("org.example:lib", "1.0.0", fixed, "GHSA-maven-0001", fp, findings.SeverityMedium)
	f.Location.FilePath = "pom.xml"
	f.Metadata["ecosystem"] = "maven"
	return f
}

func iac(rule, file string, line int, fp string) findings.Finding {
	return findings.Finding{
		RuleID: rule, Severity: findings.SeverityMedium, Confidence: findings.ConfidenceMedium,
		Location: findings.Location{FilePath: file, StartLine: line}, Message: rule + " at " + file, Fingerprint: fp,
	}
}

func promptInjection() findings.Finding {
	return findings.Finding{
		RuleID: "TAINT-AI-001", Severity: findings.SeverityHigh, Confidence: findings.ConfidenceMedium,
		Location:    findings.Location{FilePath: "src/routes/assistant.js", StartLine: 9},
		Message:     "Untrusted input reaches prompt_injection sink",
		Fingerprint: "fp-taint",
		Metadata:    map[string]string{"vuln_class": "prompt_injection"},
	}
}

func authz() findings.Finding {
	return findings.Finding{
		RuleID: "AUTHZ-001", Severity: findings.SeverityHigh, Confidence: findings.ConfidenceMedium,
		Location:    findings.Location{FilePath: "src/routes/invoices.js", StartLine: 14},
		Message:     "GET /invoices/:id reads a record by id with no ownership check",
		Fingerprint: "fp-authz",
	}
}

func writeTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"package.json": `{"dependencies":{"axios":"1.7.4","express":"4.21.2"}}`,
		// Real-shaped: express 4.21.2 declares body-parser 1.20.3 exactly.
		"package-lock.json": `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"axios":"1.7.4","express":"4.21.2"}},
"node_modules/axios":{"version":"1.7.4"},
"node_modules/express":{"version":"4.21.2","dependencies":{"body-parser":"1.20.3"}},
"node_modules/body-parser":{"version":"1.20.3"}}}`,
		"k8s/pod.yaml": "spec:\n  securityContext:\n    privileged: true\n",
		".github/workflows/ci.yml": "jobs:\n  b:\n    steps:\n      - run: make\n        continue-on-error: true\n" +
			"      - uses: actions/checkout@v4\n",
	}
	for name, body := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func fixtureFindings() []findings.Finding {
	return []findings.Finding{
		dep("axios", "1.7.4", "1.18.0", "GHSA-axios-0001", "fp-a1", findings.SeverityHigh),
		dep("axios", "1.7.4", "1.20.0", "GHSA-axios-0002", "fp-a2", findings.SeverityMedium),
		dep("body-parser", "1.20.3", "1.20.9", "GHSA-bp-0001", "fp-b1", findings.SeverityHigh),
		dep("express", "4.17.0", "5.0.0", "GHSA-ex-0001", "fp-e1", findings.SeverityHigh),
		dep("left-pad", "1.0.0", "", "GHSA-lp-0001", "fp-l1", findings.SeverityLow),
		mavenDep("1.0.5", "fp-m1"),
		iac("IAC-007", "k8s/pod.yaml", 3, "fp-pod"),
		iac("IAC-018", ".github/workflows/ci.yml", 5, "fp-coe"),
		iac("IAC-013", ".github/workflows/ci.yml", 6, "fp-pin"),
		promptInjection(),
		authz(),
	}
}

func TestBuildClassifiesEveryIssue(t *testing.T) {
	root := writeTree(t)
	plan := Build(Input{Findings: fixtureFindings(), Root: root})

	byTitle := map[Kind][]Item{}
	for _, it := range plan.Items {
		byTitle[it.Kind] = append(byTitle[it.Kind], it)
	}
	want := map[Kind]Class{
		KindUpgrade:       ClassSafe,
		KindMajorUpgrade:  ClassReview,
		KindManualUpgrade: ClassInfo,
		KindNoFix:         ClassInfo,
		KindActionsPin:    ClassSafe,
		KindContentPatch:  "", // one safe, one review: checked below
		KindCode:          ClassInfo,
	}
	for kind, class := range want {
		if len(byTitle[kind]) == 0 {
			t.Errorf("no item of kind %s", kind)
			continue
		}
		for _, it := range byTitle[kind] {
			if class != "" && it.Class != class {
				t.Errorf("%s item %d is %s, want %s", kind, it.N, it.Class, class)
			}
		}
	}
	var safePatch, reviewPatch bool
	for _, it := range byTitle[KindContentPatch] {
		safePatch = safePatch || it.Class == ClassSafe
		reviewPatch = reviewPatch || it.Class == ClassReview
	}
	if !safePatch || !reviewPatch {
		t.Errorf("want one safe and one review content patch, got %+v", byTitle[KindContentPatch])
	}
	if plan.Safe+plan.Review+plan.Info != len(plan.Items) {
		t.Errorf("counts %d+%d+%d do not add up to %d items", plan.Safe, plan.Review, plan.Info, len(plan.Items))
	}
}

// Every finding the assessment lists belongs to exactly one item: a plan that
// dropped one would be an all-clear for it.
func TestEveryFindingIsInExactlyOneItem(t *testing.T) {
	ff := fixtureFindings()
	plan := Build(Input{Findings: ff, Root: writeTree(t)})
	seen := map[string]int{}
	for _, it := range plan.Items {
		for _, fp := range it.Fingerprints {
			seen[fp]++
		}
	}
	for i := range ff {
		if seen[ff[i].Fingerprint] != 1 {
			t.Errorf("finding %s is in %d items, want 1", ff[i].Fingerprint, seen[ff[i].Fingerprint])
		}
	}
}

func TestPlanGolden(t *testing.T) {
	plan := Build(Input{Findings: fixtureFindings(), Root: writeTree(t)})
	var buf bytes.Buffer
	if err := RenderPlan(&buf, plan); err != nil {
		t.Fatal(err)
	}
	golden(t, "plan.golden", buf.String())
}

func TestPlanJSONGolden(t *testing.T) {
	plan := Build(Input{Findings: fixtureFindings(), Root: writeTree(t)})
	var buf bytes.Buffer
	if err := WritePlanJSON(&buf, plan); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatal("plan JSON is not valid")
	}
	golden(t, "plan.json.golden", buf.String())
}

func TestPlanIsDeterministic(t *testing.T) {
	root := writeTree(t)
	var first string
	for i := 0; i < 5; i++ {
		var buf bytes.Buffer
		_ = WritePlanJSON(&buf, Build(Input{Findings: fixtureFindings(), Root: root}))
		if i == 0 {
			first = buf.String()
		} else if buf.String() != first {
			t.Fatal("same findings and files produced a different plan")
		}
	}
}

func TestTransitiveUpgradeHeldByAParentIsNotSafe(t *testing.T) {
	plan := Build(Input{Findings: fixtureFindings(), Root: writeTree(t)})
	for _, it := range plan.Items {
		if it.Upgrade == nil {
			continue
		}
		switch it.Upgrade.Package {
		case "axios":
			if it.Kind != KindUpgrade || it.Class != ClassSafe {
				t.Errorf("axios is declared in package.json and should stay safe, got %s/%s", it.Class, it.Kind)
			}
		case "body-parser":
			if it.Class != ClassReview || it.Kind != KindHeldUpgrade {
				t.Errorf("body-parser is pinned by express and must not be safe, got %s/%s", it.Class, it.Kind)
			}
			for _, want := range []string{"express@4.21.2 requires body-parser 1.20.3", `"overrides": { "body-parser": "1.20.9" }`, "upgrade express"} {
				if !strings.Contains(it.Why, want) {
					t.Errorf("why = %q, want it to contain %q", it.Why, want)
				}
			}
		}
	}
}

// A content patch whose line has moved is not offered: nothing is proposed that
// would not change a byte, and the item says what to do instead.
func TestStalePatchBecomesNeedsInformation(t *testing.T) {
	root := writeTree(t)
	if err := os.WriteFile(filepath.Join(root, "k8s", "pod.yaml"), []byte("spec:\n  securityContext:\n    privileged: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan := Build(Input{Findings: []findings.Finding{iac("IAC-007", "k8s/pod.yaml", 3, "fp-pod")}, Root: root})
	if len(plan.Items) != 1 || plan.Items[0].Class != ClassInfo || !strings.Contains(plan.Items[0].Needs, "fresh scan") {
		t.Fatalf("stale patch was not turned into a request for a fresh scan: %+v", plan.Items)
	}
}

func TestAnnotationMatchesItem(t *testing.T) {
	plan := Build(Input{Findings: fixtureFindings(), Root: writeTree(t)})
	a, ok := plan.AnnotationFor("fp-taint")
	if !ok || a.Class != ClassInfo || !strings.Contains(a.Text, "cannot fix this automatically") {
		t.Fatalf("annotation = %+v, %v", a, ok)
	}
	if _, ok := plan.AnnotationFor("no-such-fingerprint"); ok {
		t.Fatal("annotated a finding the plan does not hold")
	}
}
