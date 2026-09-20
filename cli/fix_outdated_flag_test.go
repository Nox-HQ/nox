package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// fixFlagUsage returns the usage text `nox fix -h` prints for one flag.
func fixFlagUsage(t *testing.T, flagName string) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	runFix([]string{"-h"})
	os.Stderr = saved
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	usage := string(out)
	start := strings.Index(usage, "-"+flagName+"\n")
	if start < 0 {
		t.Fatalf("`nox fix -h` does not document -%s:\n%s", flagName, usage)
	}
	rest := usage[start:]
	// The description is the indented block under the flag; the next flag
	// starts at the next line beginning with two spaces and a dash.
	if end := strings.Index(rest[1:], "\n  -"); end >= 0 {
		rest = rest[:end+1]
	}
	return rest
}

// `--outdated`'s own description told operators it was Go only, long after the
// currency pass grew a registry client: `resolveLatest` queries npm, PyPI,
// crates.io, RubyGems, Packagist and NuGet directly, and the upgrade is applied
// with that ecosystem's own tool. A flag that understates what it does is a
// flag nobody runs — the operator who reads "Go only" in a TypeScript
// repository stops reading there, which is exactly what happened.
func TestOutdatedFlagDoesNotUnderstateItsEcosystems(t *testing.T) {
	usage := fixFlagUsage(t, "outdated")

	if strings.Contains(usage, "Go only") {
		t.Errorf("-outdated still claims to be Go only: %q", usage)
	}
	for eco := range registryBase {
		if !strings.Contains(strings.ToLower(usage), eco) {
			t.Errorf("-outdated does not mention %q, which registryBase resolves against: %q", eco, usage)
		}
	}
}
