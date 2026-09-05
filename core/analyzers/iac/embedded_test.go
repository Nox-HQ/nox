package iac

import (
	"strings"
	"testing"
)

const hardenedPod = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
      - name: app
        image: nginx:1.25
        livenessProbe:
          httpGet: {path: /, port: 80}
        readinessProbe:
          httpGet: {path: /, port: 80}
        resources:
          limits: {cpu: 100m, memory: 128Mi}
          requests: {cpu: 10m, memory: 64Mi}
`

const barePod = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:latest
`

func wrap(inner string) string {
	var b strings.Builder
	b.WriteString("apiVersion: rollops.klarlabs.de/v1\nkind: RolloutConfig\nmetadata:\n  name: x\nspec:\n  target:\n    spec:\n      manifest: |\n")
	for _, l := range strings.Split(strings.TrimRight(inner, "\n"), "\n") {
		b.WriteString("        " + l + "\n")
	}
	return b.String()
}

func embeddedRuleIDs(t *testing.T, path, content string) map[string]int {
	t.Helper()
	got, err := NewAnalyzer().ScanFile(path, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for i := range got {
		out[got[i].RuleID]++
	}
	return out
}

// A manifest embedded in a block scalar must be checked exactly like the same
// manifest standing alone. Absence rules used to skip it entirely: the block's
// contents are a string VALUE of the outer document, not a document, so a rule
// bounded to a YAML document never looked inside — and reported nothing, which
// is indistinguishable from a clean result.
func TestEmbeddedManifestGetsTheSameRulesAsAPlainOne(t *testing.T) {
	plain := embeddedRuleIDs(t, "deploy.yaml", barePod)
	nested := embeddedRuleIDs(t, "rollout.yaml", wrap(barePod))

	for id := range plain {
		if nested[id] == 0 {
			t.Errorf("%s fires on the plain manifest but not the embedded one", id)
		}
	}
	if len(nested) < len(plain) {
		t.Errorf("embedded saw %d rules, plain saw %d", len(nested), len(plain))
	}
}

// Some absence rules DO already fire on the outer file — their anchor is raw
// text, so `kind: Deployment` inside the block matches, and a span of "file"
// then searches the whole thing. Re-reporting those from the extracted document
// would double them, which is the defect retiring IAC-374 just removed.
func TestEmbeddedScanDoesNotDoubleReport(t *testing.T) {
	for id, n := range embeddedRuleIDs(t, "rollout.yaml", wrap(barePod)) {
		if n > 1 {
			t.Errorf("%s reported %d times for one embedded manifest", id, n)
		}
	}
}

// The extraction must not invent findings: a hardened manifest stays clean
// whether or not it is embedded.
func TestHardenedEmbeddedManifestStaysClean(t *testing.T) {
	plain := embeddedRuleIDs(t, "deploy.yaml", hardenedPod)
	nested := embeddedRuleIDs(t, "rollout.yaml", wrap(hardenedPod))

	for id := range nested {
		if plain[id] == 0 {
			t.Errorf("%s fires only when the manifest is embedded — the extraction invented it", id)
		}
	}
}

// A block scalar that is not a Kubernetes manifest must be left alone. Scanning
// a shell script or a licence text as though it were a workload is how a
// precision fix becomes a false-positive generator.
func TestNonManifestBlockScalarsAreIgnored(t *testing.T) {
	cases := map[string]string{
		"a shell script":  "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\ndata:\n  run.sh: |\n    #!/bin/sh\n    echo hello\n",
		"prose":           "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\ndata:\n  notes: |\n    kind of a long note\n    apiVersion of the API we use\n",
		"no block scalar": barePod,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			for i, em := range extractEmbeddedManifests([]byte(content)) {
				t.Errorf("extracted %d: %q", i, string(em.content))
			}
		})
	}
}

// A finding's line must point at the resource inside the outer file, or the
// operator opens the file and sees something unrelated.
func TestEmbeddedFindingsPointAtTheOuterFileLine(t *testing.T) {
	content := wrap(barePod)
	got, err := NewAnalyzer().ScanFile("rollout.yaml", []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(content, "\n")

	var checked int
	for i := range got {
		if got[i].Metadata["embedded_manifest"] != "true" {
			continue
		}
		checked++
		ln := got[i].Location.StartLine
		if ln < 1 || ln > len(lines) {
			t.Fatalf("%s reported line %d, file has %d lines", got[i].RuleID, ln, len(lines))
		}
		// Every absence rule here anchors on the workload, so the line it
		// names must sit inside the embedded document, not in the wrapper.
		if ln < 9 {
			t.Errorf("%s reported line %d, which is the wrapper, not the manifest", got[i].RuleID, ln)
		}
	}
	if checked == 0 {
		t.Fatal("no embedded findings produced, so the line assertion proves nothing")
	}
}
