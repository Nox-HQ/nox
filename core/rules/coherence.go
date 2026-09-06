package rules

import (
	"fmt"
	"sort"
	"strings"
)

// validAbsenceSpans are the span modes absenceSpan() implements. Anything else
// falls to its default branch and returns nil for every anchor, which disables
// the rule without any error: it loads, it lists, and it never fires.
var validAbsenceSpans = map[string]bool{
	"":                true, // treated as "file"
	"file":            true,
	"line":            true,
	"line-continued":  true,
	"brace-block":     true,
	"brace-enclosing": true,
	"yaml-block":      true,
	"yaml-doc":        true,
}

// CheckCoherence reports declared semantics that the rule's own evaluation path
// cannot consume.
//
// A rule is a set of fields and a matcher type, and nothing has ever connected
// the two. `validateRule` checks that the ID is non-empty, the matcher type is
// known and the severity is known — none of which notice a rule whose fields
// are read by a path it never takes. The result is a rule that loads without
// complaint, appears in `nox rules`, and finds nothing. That failure is
// indistinguishable from a rule that ran and found nothing wrong, which is the
// shape this repository keeps being bitten by: `jsonpath`, `yamlpath` and
// `heuristic` were removed from ValidMatcherTypes for exactly this reason —
// they validated at load and were served by a stub that matched nothing.
//
// The absence matcher has two evaluation paths and they read DISJOINT field
// sets. structuralAbsence parses the document and reads AbsenceResourceTypes,
// AbsencePropertyPath, AbsenceRequireAll, AbsenceCompanion* and
// AbsenceSubjectMinInt; it returns "undecided" unless resource types are set
// AND one of companion types or property path is. Everything else falls through
// to the text path, which reads AbsenceAnchor, AbsenceProperty, AbsenceSpan and
// AbsenceRequire and ignores the first group entirely.
//
// So a rule declaring `absence_subject_min_int` without a property path loads,
// lists, and applies no precondition at all — the precondition is not wrong,
// it is not read. That is what this function refuses.
func (r *Rule) CheckCoherence() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	structuralOnly := r.structuralOnlyFields()
	reachesStructural := len(r.AbsenceResourceTypes) > 0 &&
		(len(r.AbsenceCompanionTypes) > 0 || len(r.AbsencePropertyPath) > 0)

	if r.MatcherType != "absence" {
		if fields := r.absenceFields(); len(fields) > 0 {
			add("matcher_type is %q, but %s only the absence matcher reads",
				r.MatcherType, describeFields(fields))
		}
	} else {
		if !validAbsenceSpans[r.AbsenceSpan] {
			add("absence_span %q is not a span absenceSpan() implements, so every anchor "+
				"resolves to no span and the rule cannot fire", r.AbsenceSpan)
		}
		// The text path needs both an anchor and a property: compile("")
		// returns a nil regexp and Match gives up, silently. A rule that
		// reaches the structural path does not need them, because the document
		// answers instead.
		if !reachesStructural {
			if r.AbsenceAnchor == "" {
				add("no absence_anchor and no structural descriptor, so the text path " +
					"returns nil before it looks at anything")
			}
			if r.AbsenceProperty == "" {
				add("no absence_property and no structural descriptor, so the text path " +
					"returns nil before it looks at anything")
			}
		}
		if len(structuralOnly) > 0 && !reachesStructural {
			add("%s read only by structuralAbsence, which this rule never reaches: "+
				"it needs absence_resource_types AND one of absence_property_path or "+
				"absence_companion_types. As written the field is inert",
				describeFields(structuralOnly))
		}
		if len(r.AbsenceResourceTypes) > 0 && !reachesStructural {
			add("absence_resource_types is set with neither absence_property_path nor " +
				"absence_companion_types, so structuralAbsence returns undecided and the " +
				"resource types are never consulted")
		}
		if (r.AbsenceCompanionLink != "" || r.AbsenceCompanionPath != "") &&
			len(r.AbsenceCompanionTypes) == 0 {
			add("absence_companion_link/path without absence_companion_types: the companion " +
				"branch is selected by the types, so the link and path are never read")
		}
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("rule %s is incoherent: %s", r.ID, strings.Join(problems, "; "))
}

// absenceFields names every Absence* field this rule sets.
func (r *Rule) absenceFields() []string {
	var f []string
	if r.AbsenceAnchor != "" {
		f = append(f, "absence_anchor")
	}
	if r.AbsenceProperty != "" {
		f = append(f, "absence_property")
	}
	if r.AbsenceRequire != "" {
		f = append(f, "absence_require")
	}
	if r.AbsenceSpan != "" {
		f = append(f, "absence_span")
	}
	return append(f, r.structuralOnlyFields()...)
}

// structuralOnlyFields names the fields ONLY structuralAbsence reads. The text
// path does not look at any of them, so setting one on a rule that falls
// through is a declaration with no reader.
func (r *Rule) structuralOnlyFields() []string {
	var f []string
	if len(r.AbsenceResourceTypes) > 0 {
		f = append(f, "absence_resource_types")
	}
	if len(r.AbsencePropertyPath) > 0 {
		f = append(f, "absence_property_path")
	}
	if r.AbsenceRequireAll {
		f = append(f, "absence_require_all")
	}
	if len(r.AbsenceSubjectMinInt) > 0 {
		f = append(f, "absence_subject_min_int")
	}
	if len(r.AbsenceCompanionTypes) > 0 {
		f = append(f, "absence_companion_types")
	}
	if r.AbsenceCompanionLink != "" {
		f = append(f, "absence_companion_link")
	}
	if r.AbsenceCompanionPath != "" {
		f = append(f, "absence_companion_path")
	}
	return f
}

// describeFields renders a field list with the right verb, so the message reads
// as a sentence in both the one-field and many-field cases.
func describeFields(fields []string) string {
	sorted := append([]string{}, fields...)
	sort.Strings(sorted)
	if len(sorted) == 1 {
		return sorted[0] + " is a field"
	}
	return strings.Join(sorted, ", ") + " are fields"
}
