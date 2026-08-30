package findings

import (
	"reflect"
	"testing"
)

// fingerprintRole classifies one field of Finding by its relationship to the
// fingerprint.
type fingerprintRole int

const (
	// notAnIngredient — changing this field must leave the fingerprint alone.
	// Every waiver in every consuming repository depends on that: a baseline
	// entry, a VEX statement and a `nox:ignore` comment are all keyed on a
	// fingerprint or a rule ID, so a field that silently joined the hash would
	// un-waive findings that were already accepted.
	notAnIngredient fingerprintRole = iota
	// ingredient — changing this field must move the fingerprint. Asserted in
	// that direction too, because a classification that is never checked
	// against reality is just a comment.
	ingredient
	// ingredientV1Only — start_line, which V2 deliberately dropped.
	ingredientV1Only
	// theOutput — the fingerprint field itself.
	theOutput
)

// fingerprintIngredients is the closed set. Every field of Finding must appear
// here or TestFingerprintIngredientsAreClosed fails by name.
//
// That is the whole point of the table. Track C5 turns Finding into the output
// of adjudication, and the tempting shape for it — a verdict the finding
// carries, an explanation appended to the message — reaches straight into the
// hash. Message is an ingredient. Writing "not reachable" onto the end of it
// moves the fingerprint of every finding adjudication touches, in a release
// that fixed nothing in the consumer's code. This table is where that gets
// caught: a new field is unclassified until someone decides, in writing,
// which side of the line it sits on.
var fingerprintIngredients = map[string]fingerprintRole{
	"ID":                   notAnIngredient,
	"RuleID":               ingredient,
	"Severity":             notAnIngredient,
	"Confidence":           notAnIngredient,
	"Location.FilePath":    ingredient,
	"Location.StartLine":   ingredientV1Only,
	"Location.EndLine":     notAnIngredient,
	"Location.StartColumn": notAnIngredient,
	"Location.EndColumn":   notAnIngredient,
	"Message":              ingredient,
	"Fingerprint":          theOutput,
	"Metadata":             notAnIngredient,
	"Status":               notAnIngredient,
	"Exploitability":       notAnIngredient,
	"EvidenceConfidence":   notAnIngredient,
	"RetiredRuleIDs":       notAnIngredient,
	"AliasFingerprints":    notAnIngredient,
}

func contractBase() Finding {
	return Finding{
		ID:         "SEC-003-abc123abc123",
		RuleID:     "SEC-003",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Location: Location{
			FilePath: "app/config.py", StartLine: 12, EndLine: 12,
			StartColumn: 4, EndColumn: 40,
		},
		Message:           "hardcoded GitHub token",
		Metadata:          map[string]string{"kind": "github_pat"},
		Status:            StatusNew,
		Exploitability:    "POTENTIAL",
		RetiredRuleIDs:    []string{"SEC-903"},
		AliasFingerprints: []string{"deadbeef"},
	}
}

// fingerprintVia runs the real production path — FindingSet.Add — rather than
// calling ComputeFingerprint directly. Add is where the ingredients are chosen,
// so a change that starts hashing Status would be invisible to a test that
// passed the three arguments itself.
func fingerprintVia(f Finding) string {
	f.Fingerprint = ""
	fs := NewFindingSet()
	fs.Add(f)
	return fs.Findings()[0].Fingerprint
}

// mutate returns a copy of f with the field at path changed to a different
// value of the same type.
func mutate(t *testing.T, f Finding, path string) Finding {
	t.Helper()
	v := reflect.ValueOf(&f).Elem()
	for _, name := range splitPath(path) {
		v = v.FieldByName(name)
		if !v.IsValid() {
			t.Fatalf("no field %q on Finding", path)
		}
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(v.String() + "-changed")
	case reflect.Int:
		v.SetInt(v.Int() + 1)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		iter := v.MapRange()
		for iter.Next() {
			m.SetMapIndex(iter.Key(), iter.Value())
		}
		m.SetMapIndex(reflect.ValueOf("added"), reflect.ValueOf("value"))
		v.Set(m)
	case reflect.Slice:
		v.Set(reflect.Append(v, reflect.ValueOf("added")))
	default:
		t.Fatalf("mutate: unhandled kind %s at %q; extend this switch", v.Kind(), path)
	}
	return f
}

func splitPath(path string) []string {
	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			return []string{path[:i], path[i+1:]}
		}
	}
	return []string{path}
}

// fieldPaths enumerates every field of Finding, descending one level into
// Location, so the classification table cannot go stale silently.
func fieldPaths() []string {
	var out []string
	ft := reflect.TypeOf(Finding{})
	for i := 0; i < ft.NumField(); i++ {
		f := ft.Field(i)
		if f.Type.Kind() == reflect.Struct {
			for j := 0; j < f.Type.NumField(); j++ {
				out = append(out, f.Name+"."+f.Type.Field(j).Name)
			}
			continue
		}
		out = append(out, f.Name)
	}
	return out
}

// TestFingerprintIngredientsAreClosed is Track C4's contract, and the gate on
// C5.
//
// It asserts two things at once. Every field of Finding is classified, so a
// field added by a later track cannot join or dodge the hash by accident; and
// every classification is true, checked by mutating the field and looking at
// what the fingerprint does. A table that says "Severity is not an ingredient"
// and is never confronted with a Severity change documents an intention, not a
// property.
func TestFingerprintIngredientsAreClosed(t *testing.T) {
	for _, version := range []FingerprintVersion{FingerprintV1, FingerprintV2} {
		t.Run(map[FingerprintVersion]string{FingerprintV1: "v1", FingerprintV2: "v2"}[version], func(t *testing.T) {
			withFingerprintVersion(t, version)

			classified := make(map[string]bool, len(fingerprintIngredients))
			base := fingerprintVia(contractBase())

			for _, path := range fieldPaths() {
				role, ok := fingerprintIngredients[path]
				if !ok {
					t.Errorf("field %q is not classified in fingerprintIngredients. "+
						"Decide whether changing it may move a fingerprint: if it may, "+
						"every baseline entry, VEX statement and nox:ignore comment "+
						"written against the findings it appears on stops matching.", path)
					continue
				}
				classified[path] = true
				if role == theOutput {
					continue
				}

				got := fingerprintVia(mutate(t, contractBase(), path))
				isIngredient := role == ingredient ||
					(role == ingredientV1Only && version == FingerprintV1)

				switch {
				case isIngredient && got == base:
					t.Errorf("%q is classified as a fingerprint ingredient under %s "+
						"but changing it left the fingerprint alone; the classification is wrong",
						path, versionName(version))
				case !isIngredient && got != base:
					t.Errorf("changing %q moved the fingerprint under %s. Every waiver "+
						"keyed on the old value stops matching, in repositories that "+
						"changed nothing.", path, versionName(version))
				}
			}

			for path := range fingerprintIngredients {
				if !classified[path] {
					t.Errorf("fingerprintIngredients classifies %q, which Finding no longer has; "+
						"remove it so the table keeps meaning something", path)
				}
			}
		})
	}
}

func versionName(v FingerprintVersion) string {
	if v == FingerprintV1 {
		return "v1"
	}
	return "v2"
}
