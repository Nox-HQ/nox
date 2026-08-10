package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCfg(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A key nox does not understand is silently ignored, so a .nox.yaml can
// describe a policy that is not in force and nothing says so.
//
// This matters more here than in an ordinary tool. `suppressions:` is not a
// real key — write it and nox accepts the file, suppresses nothing, and scans
// as though you had asked for nothing. Misspell `plugins.required` and every
// plugin silently stops running. In both cases the operator believes the
// config is doing something it is not, and the scan reports success.
//
// nox already models this correctly elsewhere: an installed-but-undeclared
// plugin produces a [degraded] line naming the impact rather than a quiet
// pass. Config typos deserve the same treatment.
func TestUnknownConfigKeysAreReported(t *testing.T) {
	tests := []struct {
		name    string
		cfg     string
		wantKey []string
	}{
		{
			name:    "a key that does not exist at all",
			cfg:     "version: 1\nsuppressions:\n  - rule: VULN-001\n",
			wantKey: []string{"suppressions"},
		},
		{
			name:    "a misspelled top-level key",
			cfg:     "excludes_paths:\n  - vendor/\n",
			wantKey: []string{"excludes_paths"},
		},
		{
			name:    "a misspelled nested key",
			cfg:     "plugins:\n  reqiured:\n    - nox/sast\n",
			wantKey: []string{"reqiured"},
		},
		{
			name:    "several at once are all named",
			cfg:     "suppressions: []\nexcludes_paths: []\n",
			wantKey: []string{"suppressions", "excludes_paths"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeCfg(t, dir, tc.cfg)

			unknown := UnknownConfigKeys(dir)
			joined := strings.Join(unknown, " ")
			for _, k := range tc.wantKey {
				if !strings.Contains(joined, k) {
					t.Errorf("unknown keys %v do not mention %q", unknown, k)
				}
			}
		})
	}
}

// A correct config must stay silent, or the warning becomes noise and gets
// filtered out — which would leave the real case invisible again.
func TestValidConfigReportsNoUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, `scan:
  exclude:
    - vendor/
plugins:
  required:
    - nox/taint-analysis
output:
  format: json
`)
	if got := UnknownConfigKeys(dir); len(got) != 0 {
		t.Errorf("a valid config reported unknown keys: %v", got)
	}
}

// No config, or an unreadable one, is not an unknown-key problem — the loader
// already handles those, and reporting here would double up.
func TestMissingConfigReportsNothing(t *testing.T) {
	if got := UnknownConfigKeys(t.TempDir()); len(got) != 0 {
		t.Errorf("absent config reported unknown keys: %v", got)
	}
}
