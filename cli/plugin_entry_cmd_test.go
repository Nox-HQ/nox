package main

import (
	"os"
	"strings"
	"testing"
)

// The plugin release workflows sign with cosign v4, which writes a single
// checksums.txt.sigstore.json and no detached .sig. Emitting the v3 names
// (.sig + .sig.bundle) produced entries pointing at files that were never
// uploaded: the signature download 404s, the artifact is classified
// "unverified", and the install is blocked by the default trust policy. Every
// plugin version published after the move to v4 was uninstallable because of it.
func TestPluginEntry_UsesCosignV4BundleName(t *testing.T) {
	src, err := os.ReadFile("plugin_entry_cmd.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(src)
	if !strings.Contains(s, "checksums.txt.sigstore.json") {
		t.Error("entry generation must emit the cosign v4 bundle name checksums.txt.sigstore.json")
	}
	if strings.Contains(s, "checksums.txt.sig.bundle") {
		t.Error("entry generation must not emit the cosign v3 bundle name .sig.bundle; the releases do not publish it")
	}
	if strings.Contains(s, `CosignSigURL:`) {
		t.Error("cosign v4 has no detached .sig; CosignSigURL must be left empty so omitempty drops it")
	}
}
