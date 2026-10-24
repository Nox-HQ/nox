// Package plugincap says what an installed analysis plugin is FOR, in the words
// a person who has never heard of plugins would use, and whether leaving it off
// leaves a gap.
//
// Nox's vision is that a developer never has to know which internal component
// performs which check. The scan's account of what it did not do used to name
// plugins ("15 plugins are not listed in plugins.required"), which asks the
// reader to know what each one is and to pick. This package is the single place
// that maps a plugin name to a capability and a class, so the assessment can say
// "API abuse patterns (rate limiting, error detail) were not checked" and keep the plugin names for
// --verbose and findings.json.
//
// The class is not decoration. It records a measured decision (see
// docs/plugin-defaults.md): a plugin whose check core already performs, or that
// was measured to turn "did not check" into a negative, is not a gap the reader
// needs to act on, and listing it under "Not checked" would send them to enable
// something that hurts. What did not run is still accounted for in full in the
// degradation's Detail; only its presentation is capability-shaped.
package plugincap

import (
	"fmt"
	"sort"
	"strings"
)

// Class is what leaving a plugin off means for a scan.
type Class int

const (
	// Optional is a scan-time check core does not perform. It is a real gap, so
	// the assessment names it, and it stays off by default because it has not
	// met the precision bar for running unasked.
	Optional Class = iota
	// Live needs a running target, a cluster or an endpoint: it sends traffic
	// or reads live state. It is active by definition and never part of
	// `nox scan`; `nox attack` is where it is planned and authorized.
	Live
	// Covered is a check core now performs itself. The plugin restates it, so
	// leaving it off is not a gap and running it double-counts.
	Covered
	// Retired was measured to hurt: unsound output, or noise that buries the
	// signal. Never offered as something to enable.
	Retired
	// Adjunct annotates, plans or reports rather than checks. Leaving it off
	// removes no check.
	Adjunct
)

// Entry describes one plugin.
type Entry struct {
	// Capability is the check in plain words, lowercase, with no plugin name.
	Capability string
	Class      Class
}

// unknown is what a plugin nobody has classified is treated as: a check that
// may or may not duplicate core, named without guessing at its purpose.
var unknown = Entry{Capability: "additional checks from a third-party plugin", Class: Optional}

// classify is keyed by registry name. The evidence for each class is in
// docs/plugin-defaults.md; change the two together. A switch rather than a
// table so no entry's formatting depends on its neighbours.
func classify(name string) (Entry, bool) {
	switch name {
	case "nox/api-abuse":
		return Entry{"API abuse patterns (rate limiting, error detail)", Optional}, true
	case "nox/attack-surface":
		return Entry{"exposed endpoints and admin or debug routes", Optional}, true
	case "nox/depconfusion":
		return Entry{"dependency-confusion exposure", Optional}, true
	case "freshness":
		return Entry{"dependency freshness (needs the network)", Optional}, true
	case "nox/dast":
		return Entry{"probing a running web application", Live}, true
	case "nox/k8s-runtime":
		return Entry{"inspecting running Kubernetes workloads", Live}, true
	case "nox/ai-eval":
		return Entry{"adversarial prompts against a live chat endpoint", Live}, true
	case "nox/container":
		return Entry{"container image configuration", Covered}, true
	case "nox/taint-analysis":
		return Entry{"data-flow analysis", Covered}, true
	case "nox/reachability":
		return Entry{"dependency reachability", Retired}, true
	case "nox/triage-agent":
		return Entry{"pattern triage", Retired}, true
	case "nox/threat-model":
		return Entry{"pattern-based threat modelling", Retired}, true
	case "nox/threat-enrich":
		return Entry{"threat context on findings", Adjunct}, true
	case "nox/remediate":
		return Entry{"fix planning", Adjunct}, true
	case "nox/grc":
		return Entry{"compliance reporting", Adjunct}, true
	}
	return Entry{}, false
}

// Lookup returns the entry for a plugin name, with any `@constraint` removed.
// A plugin not in the catalog (a third party's, or one newer than this nox) is
// treated as an optional check rather than hidden, because a gap that is not
// named is the worse mistake.
func Lookup(name string) Entry {
	if i := strings.Index(name, "@"); i >= 0 {
		name = name[:i]
	}
	if e, ok := classify(strings.TrimSpace(name)); ok {
		return e
	}
	return unknown
}

// Capabilities returns the distinct capabilities among names whose class is c,
// sorted so the same set always renders the same way.
func Capabilities(names []string, c Class) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		e := Lookup(n)
		if e.Class != c || seen[e.Capability] {
			continue
		}
		seen[e.Capability] = true
		out = append(out, e.Capability)
	}
	sort.Strings(out)
	return out
}

// undeclaredMarker separates the count from the names in the degradation
// detail. UndeclaredDetail writes it and Undeclared reads it; they are one
// format and the test pins the round trip.
const undeclaredMarker = " are not listed in plugins.required and did not run: "

// UndeclaredDetail is the degradation detail for installed plugins the project
// did not enable. It keeps the plugin names, which belong in findings.json and
// behind --verbose.
func UndeclaredDetail(names []string) string {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	return fmt.Sprintf("%d installed plugin(s)%s%s", len(sorted), undeclaredMarker, strings.Join(sorted, ", "))
}

// Undeclared recovers the plugin names from a detail UndeclaredDetail wrote. ok
// is false for any other text, so a caller can fall back to wording that names
// nothing rather than guessing.
func Undeclared(detail string) (names []string, ok bool) {
	_, rest, found := strings.Cut(detail, undeclaredMarker)
	if !found {
		return nil, false
	}
	for _, n := range strings.Split(rest, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	return names, len(names) > 0
}

// Join renders a list of capabilities as "a, b and c".
func Join(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
