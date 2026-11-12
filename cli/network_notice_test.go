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

// Maven parent and BOM coordinates leave the machine in their own request;
// a scan that sent some says so, and one that sent none prints nothing.
func TestMavenNetworkNotice(t *testing.T) {
	t.Setenv(nox.IntelligenceEndpointEnv, "")
	def := func() *nox.ScanConfig { return &nox.ScanConfig{} }
	if got := mavenNetworkNotice(def(), 0); got != "" {
		t.Errorf("no POMs requested printed %q", got)
	}
	got := mavenNetworkNotice(def(), 3)
	for _, want := range []string{"3 published parent or BOM POM(s)", "Maven Central", "https://intel.klarlabs.de"} {
		if !strings.Contains(got, want) {
			t.Errorf("notice %q lacks %q", got, want)
		}
	}
}

// A digest-pinned base image is pulled from its registry, the token service
// the registry names and the storage host it redirects to. None of them is the
// advisory source, so the dependency notice does not cover them.
func TestImageNetworkNotice(t *testing.T) {
	got := imageNetworkNotice([]string{"auth.docker.io", "production.cloudflare.docker.com", "registry-1.docker.io"})
	for _, want := range []string{"[network]", "auth.docker.io", "production.cloudflare.docker.com", "registry-1.docker.io",
		"scan.images.enabled: false", "--offline"} {
		if !strings.Contains(got, want) {
			t.Errorf("notice lacks %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "\n") != 0 {
		t.Errorf("must be one line, got:\n%s", got)
	}
	if got := imageNetworkNotice(nil); got != "" {
		t.Errorf("the image cache answered, so nothing was requested; got %q", got)
	}
}

// The go command fetches modules the cache lacks when nox asks it what the
// build links. The notice names where it was allowed to go and how to stop it.
func TestGoModulesNetworkNotice(t *testing.T) {
	got := goModulesNetworkNotice([]string{"https://proxy.golang.org", "direct"})
	for _, want := range []string{"[network]", "https://proxy.golang.org", "the modules' own source hosts", "GOPRIVATE",
		"GOPROXY=off", "--offline"} {
		if !strings.Contains(got, want) {
			t.Errorf("notice lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "direct") {
		t.Errorf("\"direct\" is the go command's word, not a host a reader can recognise:\n%s", got)
	}
	if strings.Count(got, "\n") != 0 {
		t.Errorf("must be one line, got:\n%s", got)
	}
	if got := goModulesNetworkNotice(nil); got != "" {
		t.Errorf("the module cache answered, so nothing was requested; got %q", got)
	}
}

// The signed feeds are requests of their own: a project with no dependency
// still asks for the slopsquat feed, and the dependency notice is silent then.
func TestFeedNetworkNotice(t *testing.T) {
	if got := feedNetworkNotice(nil); got != "" {
		t.Errorf("no feed requested, want no notice, got %q", got)
	}

	one := feedNetworkNotice([]string{"https://intel.klarlabs.de/v1/feeds/slopsquat"})
	for _, want := range []string{"[network]", "https://intel.klarlabs.de/v1/feeds/slopsquat", "Nothing from the repository was sent",
		"scan.slop.disabled", "scan.mcp_feed.disabled", "--offline"} {
		if !strings.Contains(one, want) {
			t.Errorf("notice lacks %q:\n%s", want, one)
		}
	}
	if strings.Count(one, "\n") != 0 {
		t.Errorf("must be one line, got:\n%s", one)
	}

	two := feedNetworkNotice([]string{"https://intel.klarlabs.de/v1/feeds/mcp", "https://intel.klarlabs.de/v1/feeds/slopsquat"})
	if !strings.Contains(two, "/v1/feeds/mcp") || !strings.Contains(two, "/v1/feeds/slopsquat") {
		t.Errorf("notice must name both feeds:\n%s", two)
	}
}
