package core

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// unknownFieldRE pulls the offending key out of yaml.v3's strict-mode error,
// which reads: line 4: field suppressions not found in type core.ScanConfig
var unknownFieldRE = regexp.MustCompile(`field (\S+) not found`)

// UnknownConfigKeys returns the keys in .nox.yaml that nox does not understand.
//
// A security tool that silently ignores configuration is not merely untidy: it
// reports on a policy the operator did not ask for, while they believe the one
// they wrote is in force.
//
// Two real examples, both accepted without comment before this existed:
//
//   - `suppressions:` is not a key nox has. Write it and nox suppresses
//     nothing, scans everything, and passes — looking exactly like a scan whose
//     suppressions all applied.
//   - misspell `plugins.required` and every plugin stops being declared, so
//     none of them run and their findings are absent rather than clean.
//
// nox already handles the equivalent case honestly elsewhere: an
// installed-but-undeclared plugin emits a [degraded] line naming the impact
// instead of quietly passing. This brings config typos up to that standard.
//
// Reported rather than fatal, deliberately. Erroring would break every existing
// config carrying a stray key at the moment a fleet upgrades, and a scanner
// that refuses to run is its own kind of coverage loss. The operator gets a
// named list and decides.
func UnknownConfigKeys(root string) []string {
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		root = filepath.Dir(root)
	}

	data, err := os.ReadFile(filepath.Join(root, ".nox.yaml")) // #nosec G304 -- caller's scan root
	if err != nil {
		// Absent or unreadable is the loader's business, not this check's.
		// Reporting here would double up on an error the caller already has.
		return nil
	}

	seen := map[string]bool{}
	var keys []string

	// yaml.v3 reports one unknown field per decode, so decode repeatedly,
	// stripping each offender, until it stops complaining. Bounded by the
	// number of keys found so a pathological file cannot spin.
	remaining := data
	for i := 0; i < 64; i++ {
		dec := yaml.NewDecoder(bytes.NewReader(remaining))
		dec.KnownFields(true)

		var cfg ScanConfig
		err := dec.Decode(&cfg)
		if err == nil || errors.Is(err, os.ErrClosed) {
			break
		}

		m := unknownFieldRE.FindStringSubmatch(err.Error())
		if m == nil {
			// A genuine syntax error, not an unknown key. The loader surfaces
			// that separately with a better message.
			break
		}
		key := m[1]
		if seen[key] {
			break
		}
		seen[key] = true
		keys = append(keys, key)

		remaining = stripKey(remaining, key)
	}

	sort.Strings(keys)
	return keys
}

// stripKey removes the mapping entry for key so the next strict decode can
// reach the following unknown key rather than stopping at the same one.
//
// Line-based on purpose: this runs only to enumerate typos, never to produce
// the config nox actually uses, so it needs to be robust rather than exact.
func stripKey(data []byte, key string) []byte {
	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines))

	dropIndent := -1
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		indent := len(line) - len(trimmed)

		if dropIndent >= 0 {
			// Keep dropping the removed key's nested block.
			if trimmed == "" || indent > dropIndent {
				continue
			}
			dropIndent = -1
		}

		if strings.HasPrefix(trimmed, key+":") {
			dropIndent = indent
			continue
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\n"))
}
