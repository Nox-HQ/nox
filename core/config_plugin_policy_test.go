package core

import (
	"strings"
	"testing"
)

// plugin_policy is read from .nox.yaml by the plugin host, not by the scan
// engine. Until the key was declared on ScanConfig, the strict check reported
// it as one nox does not recognise, over an impact line reading "they are
// ignored, so whatever they were meant to configure is not in effect" and
// advising the operator to check for a typo.
//
// The key WAS in effect. It is how an operator widens a plugin's network or
// filesystem allowlist — the sandbox boundary itself. An operator who believed
// the message and deleted the block would silently change what a plugin is
// permitted to reach, in a scan that otherwise reported nothing wrong.
func TestPluginPolicyIsARecognisedKey(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, `plugin_policy:
  allowed_network_hosts:
    - "api.first.org"
  max_risk_class: passive
plugins:
  required:
    - nox/risk-score
`)

	if got := UnknownConfigKeys(dir); len(got) != 0 {
		t.Errorf("UnknownConfigKeys = %v, want none: plugin_policy is in force and must not be reported as ignored", got)
	}
}

// Declaring the block's schema rather than accepting it opaquely is the point:
// a misspelt key inside a security policy is exactly the case the strict check
// exists for. `allowed_network_host` (singular) grants nothing, and without
// this the operator would be told nothing while the plugin ran under a
// narrower sandbox than they wrote.
func TestTypoInsidePluginPolicyIsReported(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, `plugin_policy:
  allowed_network_host:
    - "api.first.org"
`)

	got := UnknownConfigKeys(dir)
	if len(got) != 1 || !strings.Contains(got[0], "allowed_network_host") {
		t.Errorf("UnknownConfigKeys = %v, want the misspelt allowed_network_host named", got)
	}
}
