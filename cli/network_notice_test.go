package main

import (
	"strings"
	"testing"

	nox "github.com/nox-hq/nox/core"
)

func TestNetworkNotice(t *testing.T) {
	// The hermetic test environment points both at a closed port; this test is
	// about the defaults.
	t.Setenv(nox.IntelligenceEndpointEnv, "")
	t.Setenv(nox.OSVBaseURLEnv, "")
	def := func() *nox.ScanConfig { return &nox.ScanConfig{} }

	t.Run("default scan says what was sent and how to stop it", func(t *testing.T) {
		got := networkNotice(def(), false, false, true, 7)
		for _, want := range []string{"[network]", "7 dependencies", "https://intel.klarlabs.de", "https://api.osv.dev",
			"not sent", "scan.intelligence.disabled", "--offline"} {
			if !strings.Contains(got, want) {
				t.Errorf("notice lacks %q:\n%s", want, got)
			}
		}
		if strings.Count(got, "\n") != 0 {
			t.Errorf("must be one line, got:\n%s", got)
		}
	})

	t.Run("intelligence disabled still sends to the reference database, and says so", func(t *testing.T) {
		cfg := def()
		cfg.Scan.Intelligence.Disabled = true
		got := networkNotice(cfg, false, false, true, 3)
		if strings.Contains(got, "klarlabs") || !strings.Contains(got, "https://api.osv.dev") {
			t.Errorf("must name only the reference database:\n%s", got)
		}
	})

	t.Run("nothing sent, nothing said", func(t *testing.T) {
		disabled := def()
		disabled.Scan.OSV.Disabled = true
		for name, got := range map[string]string{
			"offline":        networkNotice(def(), true, false, true, 7),
			"no-osv":         networkNotice(def(), false, true, true, 7),
			"scan.osv":       networkNotice(disabled, false, false, true, 7),
			"deps not run":   networkNotice(def(), false, false, false, 7),
			"no deps in app": networkNotice(def(), false, false, true, 0),
		} {
			if got != "" {
				t.Errorf("%s: want no notice, got %q", name, got)
			}
		}
	})
}
