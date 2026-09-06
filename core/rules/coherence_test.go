package rules

import (
	"strings"
	"testing"
)

// base returns a coherent absence rule, so each case below changes exactly one
// thing and the failure it produces is attributable to that change.
func base() Rule {
	return Rule{
		ID:              "TEST-001",
		MatcherType:     "absence",
		Severity:        "medium",
		AbsenceAnchor:   `(?i)kind\s*:\s*Deployment`,
		AbsenceProperty: `(?i)securityContext`,
		AbsenceSpan:     "yaml-block",
	}
}

func TestCoherentRulePasses(t *testing.T) {
	r := base()
	if err := r.CheckCoherence(); err != nil {
		t.Fatalf("a coherent rule was rejected: %v", err)
	}
	// And the structural shape, which reads an entirely different field set.
	s := base()
	s.AbsenceResourceTypes = []string{"Deployment"}
	s.AbsencePropertyPath = []string{"spec.template.spec.securityContext"}
	s.AbsenceRequireAll = true
	s.AbsenceSubjectMinInt = map[string]int{"spec.replicas": 2}
	if err := s.CheckCoherence(); err != nil {
		t.Fatalf("a coherent structural rule was rejected: %v", err)
	}
}

// The defect this milestone exists for: a subject precondition on a rule that
// never reaches the path which reads it. The rule loads, lists, and applies no
// precondition — and the output is identical to a rule whose precondition
// simply never excluded anything.
func TestSubjectPreconditionWithoutStructuralPathIsRejected(t *testing.T) {
	r := base()
	r.AbsenceSubjectMinInt = map[string]int{"spec.replicas": 2}

	err := r.CheckCoherence()
	if err == nil {
		t.Fatal("absence_subject_min_int without a structural descriptor was accepted; " +
			"the precondition would be silently inert")
	}
	if !strings.Contains(err.Error(), "absence_subject_min_int") {
		t.Errorf("error does not name the inert field: %v", err)
	}
}

func TestStructuralOnlyFieldsRequireTheStructuralPath(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Rule)
		want   string
	}{
		{"require_all", func(r *Rule) { r.AbsenceRequireAll = true }, "absence_require_all"},
		{"property_path alone", func(r *Rule) {
			r.AbsencePropertyPath = []string{"spec.x"}
		}, "absence_property_path"},
		{"companion types alone", func(r *Rule) {
			r.AbsenceCompanionTypes = []string{"PodDisruptionBudget"}
		}, "absence_companion_types"},
		{"resource types alone", func(r *Rule) {
			r.AbsenceResourceTypes = []string{"Deployment"}
		}, "absence_resource_types"},
		{"companion link without types", func(r *Rule) {
			r.AbsenceResourceTypes = []string{"Deployment"}
			r.AbsencePropertyPath = []string{"spec.x"}
			r.AbsenceCompanionLink = "selector"
		}, "absence_companion_link"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			tc.mutate(&r)
			err := r.CheckCoherence()
			if err == nil {
				t.Fatalf("%s was accepted on a rule that cannot read it", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not name %s: %v", tc.want, err)
			}
		})
	}
}

// A span nobody implements sends absenceSpan() to its default branch, which
// returns nil for every anchor. The rule cannot fire, and says nothing about
// it. This is the same shape as the jsonpath/yamlpath/heuristic matcher types
// that were removed from ValidMatcherTypes.
func TestUnknownAbsenceSpanIsRejected(t *testing.T) {
	for _, span := range []string{"yaml-blok", "block", "yaml_block", "FILE"} {
		r := base()
		r.AbsenceSpan = span
		if err := r.CheckCoherence(); err == nil {
			t.Errorf("absence_span %q was accepted; the rule could never fire", span)
		}
	}
	// Every implemented span, and the empty string that means "file".
	for _, span := range []string{"", "file", "line", "line-continued", "brace-block",
		"brace-enclosing", "yaml-block", "yaml-doc"} {
		r := base()
		r.AbsenceSpan = span
		if err := r.CheckCoherence(); err != nil {
			t.Errorf("implemented span %q was rejected: %v", span, err)
		}
	}
}

// compile("") returns a nil regexp and Match gives up before looking at
// anything. A rule missing either half of the text path is silent, not wrong.
func TestTextPathNeedsBothAnchorAndProperty(t *testing.T) {
	r := base()
	r.AbsenceAnchor = ""
	if err := r.CheckCoherence(); err == nil {
		t.Error("absence rule with no anchor was accepted; the text path returns nil immediately")
	}
	r = base()
	r.AbsenceProperty = ""
	if err := r.CheckCoherence(); err == nil {
		t.Error("absence rule with no property was accepted; the text path returns nil immediately")
	}

	// A structural rule legitimately needs neither: the document answers.
	s := base()
	s.AbsenceAnchor, s.AbsenceProperty = "", ""
	s.AbsenceResourceTypes = []string{"Deployment"}
	s.AbsencePropertyPath = []string{"spec.template.spec.securityContext"}
	if err := s.CheckCoherence(); err != nil {
		t.Errorf("structural rule rejected for missing text-path fields it does not use: %v", err)
	}
}

// Absence fields on a regex or entropy rule are read by nobody.
func TestAbsenceFieldsOnANonAbsenceMatcherAreRejected(t *testing.T) {
	for _, mt := range []string{"regex", "entropy"} {
		r := base()
		r.MatcherType = mt
		err := r.CheckCoherence()
		if err == nil {
			t.Errorf("matcher_type %q accepted absence fields that only the absence matcher reads", mt)
		}
	}
	// A plain regex rule with no absence fields is fine.
	clean := Rule{ID: "TEST-002", MatcherType: "regex", Severity: "low", Pattern: `foo`}
	if err := clean.CheckCoherence(); err != nil {
		t.Errorf("a plain regex rule was rejected: %v", err)
	}
}
