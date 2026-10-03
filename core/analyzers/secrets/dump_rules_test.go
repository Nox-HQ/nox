package secrets

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/rules"
)

// TestDumpRuleSet writes the BUILT secret rule set for offline analysis.
//
//	NOX_RULE_DUMP=/tmp/secrules.json go test ./core/analyzers/secrets -run TestDumpRuleSet
//
// It exists because the alternative — extracting rules from source text with
// regexes — gave wrong answers twice while the secret-rule inventory was being
// built: it paired one rule's `id:` with a different rule's `pattern:`, and it
// found 3 English-word keywords where the built set has 11. Source text is not
// the rule set. Anything reasoning about what rules actually do must read them
// from the engine that runs them.
//
// It dumps EVERY exported field of rules.Rule, found by reflection rather than
// listed by hand. Three separate wrong conclusions in this workstream came from
// a hand-written dump that omitted one: RequireContextKeywords (so
// proximity-gated rules read as file-gated), then Metadata (so SEC-161's 5.0-bit
// threshold and candidate_kinds were invisible and it was filed as a bare-token
// rule). The hand-written list had since fallen behind again -- KeywordTokens,
// OptIn, References, Retires and the absence fields were missing -- and nothing
// noticed. A partial dump does not produce a partial answer, it produces a
// confident wrong one, so the list is no longer something a person maintains.
// TestRuleDumpCoversEveryField holds that.
//
// Keys are the fields' yaml tags, the same names the rule files use and that
// scripts/secret-rule-inventory.py reads. A function-valued field cannot be
// serialised, so it is reported as present or absent: ValidateMatch becomes
// has_validate_match.
//
// Consumed by scripts/secret-rule-inventory.py; see
// docs/design/secret-rule-inventory.md.
func TestDumpRuleSet(t *testing.T) {
	path := os.Getenv("NOX_RULE_DUMP")
	if path == "" {
		t.Skip("set NOX_RULE_DUMP=<path> to dump the built rule set")
	}
	var out []map[string]any
	for _, r := range NewAnalyzer().Rules().Rules() {
		out = append(out, dumpRule(r))
	}
	if len(out) == 0 {
		t.Fatal("the built rule set is empty; the dump would describe nothing")
	}
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d rules to %s", len(out), path)
}

// dumpRule maps every exported field of a rule to its yaml-tag name.
func dumpRule(r *rules.Rule) map[string]any {
	v := reflect.ValueOf(r).Elem()
	m := make(map[string]any, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		if !f.IsExported() {
			continue
		}
		fv := v.Field(i)
		if fv.Kind() == reflect.Func {
			m["has_"+snake(f.Name)] = !fv.IsNil()
			continue
		}
		m[dumpKey(f)] = fv.Interface()
	}
	return m
}

func dumpKey(f reflect.StructField) string {
	if tag, _, _ := strings.Cut(f.Tag.Get("yaml"), ","); tag != "" && tag != "-" {
		return tag
	}
	return snake(f.Name)
}

func snake(name string) string {
	var b strings.Builder
	for i, c := range name {
		if c >= 'A' && c <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			c += 'a' - 'A'
		}
		b.WriteRune(c)
	}
	return b.String()
}

// TestRuleDumpCoversEveryField fails when rules.Rule gains a field the dump
// does not carry -- which, with reflection, can only happen if a field is
// skipped deliberately. It is the check the hand-written list never had.
func TestRuleDumpCoversEveryField(t *testing.T) {
	typ := reflect.TypeOf(rules.Rule{})
	exported := 0
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).IsExported() {
			exported++
		}
	}
	got := dumpRule(&rules.Rule{})
	if len(got) != exported {
		t.Errorf("dump carries %d keys for %d exported Rule fields: %v", len(got), exported, got)
	}
	for _, k := range []string{"id", "pattern", "metadata", "require_context_keywords",
		"exclude_context_keywords", "file_patterns", "keyword_tokens", "opt_in", "references",
		"has_validate_match"} {
		if _, ok := got[k]; !ok {
			t.Errorf("dump lacks %q, a key secret-rule-inventory.py or this file's history depends on", k)
		}
	}
}
