package core

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// InertConfigKey is a key nox parses but does not act on.
type InertConfigKey struct {
	// Key is the dotted path as written in .nox.yaml, e.g. "scan.include".
	Key string
	// GoFields are the Go field names this entry covers — the key's own field
	// plus any nested ones, since a child of an ignored parent is equally
	// ignored. The efficacy guard uses them to check nothing reads the key.
	GoFields []string
	// Reason says what nox does instead, in the operator's terms.
	Reason string
}

// inertConfigKeys enumerates the settings nox accepts and ignores.
//
// This list is an admission, not a design. Each entry exists because the field
// is in ScanConfig — so it parses, and UnknownConfigKeys stays quiet — while
// nothing in the module reads it. Without the list the operator writes the key,
// sees no complaint, and reasonably concludes it took effect.
//
// TestEveryConfigFieldIsReadOrDeclaredInert forbids a fourth entry appearing by
// accident: a new config field must either be wired up or land here with a
// reason. TestInertConfigKeysAreActuallyInert forbids an entry outliving its
// cause, so wiring a key up and forgetting to delete its apology fails too.
var inertConfigKeys = []InertConfigKey{
	{
		Key:      "compliance",
		GoFields: []string{"Compliance", "Framework"},
		Reason: "no compliance-framework filtering is applied; every finding is reported regardless " +
			"of the framework named under it",
	},
	{
		Key: "cache",
		// Dir and TTL are named here too. The name-based guard could not see
		// them: other config types also have a .Dir and a .TTL, so a selector
		// search reported them read. The compiler-backed probe in
		// config_liveness_test.go is what caught them.
		GoFields: []string{"Cache", "Dir", "TTL"},
		Reason: "nox never caches a scan, so there is nothing here to configure; the --no-cache flag " +
			"is likewise accepted and does nothing",
	},
}

// IneffectiveConfigKeys returns the inert keys actually present in the .nox.yaml
// under root, so the operator is told about the settings they wrote rather than
// every setting that exists.
//
// This is the sibling of UnknownConfigKeys and exists for the same reason. That
// check catches a key nox cannot parse; this one catches a key nox parses and
// then ignores. From where the operator sits the two are the same failure — the
// policy they wrote is not the policy in force — and only one of them used to be
// reported.
func IneffectiveConfigKeys(root string) []InertConfigKey {
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		root = filepath.Dir(root)
	}

	data, err := os.ReadFile(filepath.Join(root, ".nox.yaml")) // #nosec G304 -- caller's scan root
	if err != nil {
		// Absent or unreadable is the loader's business, as in UnknownConfigKeys.
		return nil
	}

	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		// A file that does not parse produces a load error the caller already
		// surfaces; adding to it here would only be noise.
		return nil
	}

	var found []InertConfigKey
	for _, k := range inertConfigKeys {
		if lookupPath(doc, strings.Split(k.Key, ".")) {
			found = append(found, k)
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Key < found[j].Key })
	return found
}

// lookupPath reports whether a dotted key path is present in the decoded YAML.
// Presence is what matters, not the value: writing `include: []` still says the
// operator believes include is a thing nox does.
func lookupPath(node any, path []string) bool {
	if len(path) == 0 {
		return true
	}
	m, ok := node.(map[string]any)
	if !ok {
		return false
	}
	child, ok := m[path[0]]
	if !ok {
		return false
	}
	return lookupPath(child, path[1:])
}
