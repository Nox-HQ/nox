package iac

import "testing"

// IAC-374 declared a pattern and description byte-identical to IAC-360, so a
// single `restartPolicy: Never` produced two findings a triager had to dismiss
// separately.
func TestIAC374RetiredIntoIAC360(t *testing.T) {
	const pod = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  restartPolicy: Never\n  containers:\n  - name: c\n    image: nginx:1.25\n"

	a := NewAnalyzer()
	got, err := a.ScanFile("pod.yaml", []byte(pod))
	if err != nil {
		t.Fatal(err)
	}

	var n int
	var retired []string
	for i := range got {
		switch got[i].RuleID {
		case "IAC-374":
			t.Error("IAC-374 still reports; it was retired into IAC-360")
		case "IAC-360":
			n++
			retired = got[i].RetiredRuleIDs
		}
	}
	if n != 1 {
		t.Errorf("IAC-360 fired %d times, want exactly 1", n)
	}

	// The alias is the whole point of the retirement. Without it, every
	// baseline entry, VEX statement and nox:ignore comment written against
	// IAC-374 silently stops matching.
	var found bool
	for _, id := range retired {
		if id == "IAC-374" {
			found = true
		}
	}
	if !found {
		t.Errorf("RetiredRuleIDs = %v, want IAC-374 — waivers written against the retired ID would un-waive", retired)
	}
}

// rules.go and rules_expanded.go used to convert their definitions with two
// separate loops, and the second omitted `retires`, `extraMetadata` and the
// whole absence block. A retirement declared in rules_expanded.go compiled,
// passed the dedup test's validation, and was then dropped on the way to the
// engine — un-waiving in every consuming repository. Both files now share one
// conversion; this asserts the field that was being lost survives it.
func TestExpandedRulesCarryTheirRetirements(t *testing.T) {
	var checked int
	for _, r := range builtinExpandedIaCRules() {
		if r.ID != "IAC-360" {
			continue
		}
		checked++
		if len(r.Retires) == 0 {
			t.Fatal("IAC-360 lost its Retires through the conversion")
		}
		if r.Retires[0].ID != "IAC-374" {
			t.Errorf("retires %q, want IAC-374", r.Retires[0].ID)
		}
		if r.Retires[0].Pattern == "" {
			t.Error("retirement carries no pattern, so the alias cannot be bounded to what IAC-374 actually matched")
		}
	}
	if checked == 0 {
		t.Fatal("IAC-360 not found in the expanded rules")
	}
}
