package main

import "testing"

// `output.format` in .nox.yaml silently overrode an explicit `-format` on the
// command line, because the check compared the flag's VALUE to its default:
//
//	if formatFlag == "json" && cfg.Output.Format != "" { formatFlag = ... }
//
// So `-format json` — deliberately typed by the caller — was indistinguishable
// from "flag absent", and config won. The comment above it said "CLI flags take
// precedence", which is what everyone reasonably assumed.
//
// It disabled the security gate on two repositories. A shared CI workflow ran
// `nox scan … -format json,sarif` and gated on findings.json; both repos had
// `output.format: sarif` in .nox.yaml, so findings.json was never written, the
// gating step skipped on the missing file, and a skipped step in GitHub Actions
// is a green check. 20 and 63 SARIF results respectively, neither gated.
//
// Precedence is flag > config > default: config supplies the value when the
// flag is ABSENT, never overrides one that was given.
func TestResolveOutputFormat(t *testing.T) {
	cases := []struct {
		name      string
		flagValue string // "" means the flag was not passed
		configVal string
		want      string
	}{
		{"neither: built-in default", "", "", "json"},
		{"config only", "", "sarif", "sarif"},
		{"explicit flag beats config", "json", "sarif", "json"},
		{"explicit flag, no config", "sarif", "", "sarif"},
		{"explicit multi-format beats config", "json,sarif", "sarif", "json,sarif"},
		// The regression that shipped: an explicit value that happens to equal
		// the built-in default must still win.
		{"explicit value equal to the default still wins", "json", "cdx", "json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveOutputFormat(tc.flagValue, tc.configVal); got != tc.want {
				t.Errorf("resolveOutputFormat(flag=%q, config=%q) = %q, want %q",
					tc.flagValue, tc.configVal, got, tc.want)
			}
		})
	}
}

// The output directory carried the identical defect, comparing against ".".
func TestResolveOutputDir(t *testing.T) {
	cases := []struct{ name, flagValue, configVal, want string }{
		{"neither", "", "", "."},
		{"config only", "", "nox-out", "nox-out"},
		{"explicit flag beats config", "reports", "nox-out", "reports"},
		{"explicit value equal to the default still wins", ".", "nox-out", "."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveOutputDir(tc.flagValue, tc.configVal); got != tc.want {
				t.Errorf("resolveOutputDir(flag=%q, config=%q) = %q, want %q",
					tc.flagValue, tc.configVal, got, tc.want)
			}
		})
	}
}
