package rules

import "testing"

// A pod spec whose FIRST container ("app") lacks a securityContext while a LATER
// sibling ("sidecar") has one. Because both list items sit at the same
// indentation, a yaml-block span anchored on the first "- name:" must NOT bleed
// into the sibling and borrow its securityContext — doing so would clear the
// insecure first container (a false negative).
const podInsecureFirst = `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      image: app:latest
    - name: sidecar
      image: sidecar:latest
      securityContext:
        runAsNonRoot: true
`

// Mirror: the hardened container comes first, the insecure one second. The span
// leak is forward-only (a block never absorbs preceding lines), so this case
// already reports the insecure sibling. It guards against a fix that over-swings
// and breaks the legitimate second-item detection.
const podInsecureSecond = `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      image: app:latest
      securityContext:
        runAsNonRoot: true
    - name: sidecar
      image: sidecar:latest
`

// seqAnchorRule anchors on a YAML sequence entry ("- name:") and requires each
// entry to carry a securityContext. This is the scenario the shipped rules do
// not yet exercise (they anchor on mapping keys like "containers:"), which is
// why the sibling-absorption bug is latent.
func seqAnchorRule() *Rule {
	return &Rule{
		ID:              "TEST-SEQ-SECCTX",
		AbsenceAnchor:   `(?i)- name:`,
		AbsenceProperty: `(?i)securityContext`,
		AbsenceSpan:     "yaml-block",
	}
}

func TestAbsenceMatcher_YAMLBlock_SequenceSiblingNotAbsorbed(t *testing.T) {
	m := NewAbsenceMatcher()

	// Insecure container is FIRST, hardened sibling is SECOND. The first item's
	// span must stop at the sibling "- name:" so its missing securityContext is
	// reported. Before the fix this returns 0 (false negative).
	got := m.Match([]byte(podInsecureFirst), seqAnchorRule())
	if len(got) != 1 {
		t.Fatalf("insecure-first: expected 1 finding on the unhardened container, got %d: %+v", len(got), got)
	}
	if got[0].Line != 5 {
		t.Errorf("insecure-first: expected finding on line 5 (- name: app), got line %d", got[0].Line)
	}
}

func TestAbsenceMatcher_YAMLBlock_SequenceSiblingMirrorStillFires(t *testing.T) {
	m := NewAbsenceMatcher()

	// Hardened container is FIRST, insecure sibling is SECOND. This already
	// worked; it must keep working after the fix.
	got := m.Match([]byte(podInsecureSecond), seqAnchorRule())
	if len(got) != 1 {
		t.Fatalf("insecure-second: expected 1 finding on the unhardened sibling, got %d: %+v", len(got), got)
	}
	if got[0].Line != 9 {
		t.Errorf("insecure-second: expected finding on line 9 (- name: sidecar), got line %d", got[0].Line)
	}
}

// TestAbsenceMatcher_YAMLBlock_MappingKeyAnchorAbsorbsSeqChildren guards the
// mapping-key behavior the shipped rules depend on: an anchor on "containers:"
// must still absorb its "- name:" sequence children (which sit at the same
// indent) so a securityContext on any child clears the block.
func TestAbsenceMatcher_YAMLBlock_MappingKeyAnchorAbsorbsSeqChildren(t *testing.T) {
	m := NewAbsenceMatcher()
	rule := &Rule{
		ID:              "TEST-CONTAINERS-SECCTX",
		AbsenceAnchor:   `(?i)containers:`,
		AbsenceProperty: `(?i)securityContext`,
		AbsenceSpan:     "yaml-block",
	}

	// securityContext lives on a child list item at the same indent as its
	// siblings; the "containers:" span must reach it → no finding.
	if got := m.Match([]byte(podInsecureSecond), rule); len(got) != 0 {
		t.Fatalf("mapping-key anchor should absorb seq children and see securityContext, got %d findings: %+v", len(got), got)
	}

	// No securityContext anywhere under "containers:" → the block fires once.
	noSecCtx := `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      image: app:latest
    - name: sidecar
      image: sidecar:latest
`
	if got := m.Match([]byte(noSecCtx), rule); len(got) != 1 {
		t.Fatalf("mapping-key anchor with no securityContext should fire once, got %d: %+v", len(got), got)
	}
}
