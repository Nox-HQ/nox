package plugincap

import (
	"reflect"
	"strings"
	"testing"
)

// installed is the set the measurement in docs/plugin-defaults.md was taken on.
var installed = []string{
	"freshness", "nox/ai-eval", "nox/api-abuse", "nox/attack-surface",
	"nox/container", "nox/dast", "nox/depconfusion", "nox/grc",
	"nox/k8s-runtime", "nox/reachability", "nox/remediate",
	"nox/taint-analysis", "nox/threat-enrich", "nox/threat-model",
	"nox/triage-agent",
}

// A capability is what the reader sees instead of a plugin name. One that
// says "plugin" would put the thing the vision says they should never
// need to learn back in front of them.
func TestCapabilitiesNeverNameAPlugin(t *testing.T) {
	for _, n := range installed {
		e := Lookup(n)
		if e.Capability == "" {
			t.Errorf("%s has no capability", n)
		}
		if strings.Contains(e.Capability, "plugin") || strings.Contains(e.Capability, "nox/") {
			t.Errorf("%s: capability %q mentions plugins", n, e.Capability)
		}
	}
}

// Every plugin measured in docs/plugin-defaults.md has a deliberate class, and
// the ones that must never be offered as a gap are not Optional.
func TestMeasuredClasses(t *testing.T) {
	want := []struct {
		name  string
		class Class
	}{
		{"nox/api-abuse", Optional},
		{"nox/attack-surface", Optional},
		{"nox/depconfusion", Optional},
		{"nox/dast", Live},
		{"nox/k8s-runtime", Live},
		{"nox/ai-eval", Live},
		{"nox/container", Covered},
		{"nox/taint-analysis", Covered},
		{"nox/reachability", Retired},
		{"nox/triage-agent", Retired},
		{"nox/threat-model", Retired},
		{"nox/threat-enrich", Adjunct},
		{"nox/remediate", Adjunct},
		{"nox/grc", Adjunct},
	}
	for _, w := range want {
		if got := Lookup(w.name).Class; got != w.class {
			t.Errorf("%s: class %v, want %v", w.name, got, w.class)
		}
	}
}

// A plugin nobody classified is still named as a gap. Hiding it would turn
// "installed but never run" back into silence.
func TestUnknownPluginIsAnOptionalCheck(t *testing.T) {
	e := Lookup("acme/custom-scanner@^1.2")
	if e.Class != Optional || e.Capability == "" {
		t.Fatalf("unknown plugin = %+v, want an optional check with a capability", e)
	}
}

func TestConstraintIsStrippedBeforeLookup(t *testing.T) {
	if got := Lookup("nox/container@>=0.2").Class; got != Covered {
		t.Errorf("class %v, want Covered", got)
	}
}

func TestCapabilitiesAreDistinctAndSorted(t *testing.T) {
	got := Capabilities([]string{"nox/attack-surface", "nox/api-abuse", "x/a", "y/b", "nox/container"}, Optional)
	want := []string{
		"API authorization patterns",
		"additional checks from a third-party plugin",
		"exposed endpoints and admin or debug routes",
	}
	// sort.Strings is byte order, so uppercase sorts first.
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The detail the CLI writes is the detail the assessment reads. If either side
// changes alone, the assessment falls back to naming nothing, which is safe but
// loses the capabilities; this keeps them in step.
func TestUndeclaredDetailRoundTrips(t *testing.T) {
	detail := UndeclaredDetail(installed)
	got, ok := Undeclared(detail)
	if !ok {
		t.Fatalf("could not read back %q", detail)
	}
	if !reflect.DeepEqual(got, installed) {
		t.Errorf("round trip lost names:\n got %v\nwant %v", got, installed)
	}
	if !strings.HasPrefix(detail, "15 installed plugin(s) are not listed in plugins.required and did not run: ") {
		t.Errorf("detail wording changed, which findings.json consumers match on: %q", detail)
	}
}

func TestUndeclaredRejectsOtherText(t *testing.T) {
	for _, s := range []string{"", "required plugin \"x\" is not installed", "3 installed plugin(s) are not listed in plugins.required and did not run: "} {
		if names, ok := Undeclared(s); ok {
			t.Errorf("Undeclared(%q) = %v, want not ok", s, names)
		}
	}
}

func TestJoin(t *testing.T) {
	cases := []struct {
		want string
		in   []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a and b", []string{"a", "b"}},
		{"a, b and c", []string{"a", "b", "c"}},
	}
	for _, c := range cases {
		if got := Join(c.in); got != c.want {
			t.Errorf("Join(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
