package main

import "testing"

func TestParseRepo(t *testing.T) {
	for _, c := range []struct{ in, owner, repo string }{
		{"https://github.com/nox-hq/nox-plugin-red-team", "nox-hq", "nox-plugin-red-team"},
		{"https://github.com/nox-hq/nox-plugin-grc.git", "nox-hq", "nox-plugin-grc"},
		{"https://example.com/not-github", "", ""},
		{"", "", ""},
	} {
		o, r := parseRepo(c.in)
		if o != c.owner || r != c.repo {
			t.Errorf("parseRepo(%q) = (%q,%q), want (%q,%q)", c.in, o, r, c.owner, c.repo)
		}
	}
}

// The index must only ever gain platform archives. Matching a checksums file or
// a signature bundle would put a non-installable asset in the artifact list.
func TestArtifactRe(t *testing.T) {
	match := []string{
		"nox-plugin-red-team_0.7.0_darwin_arm64.tar.gz",
		"nox-plugin-grc_0.7.0_linux_amd64.tar.gz",
		"nox-plugin-sast_0.2.1_windows_amd64.zip",
	}
	reject := []string{
		"checksums.txt",
		"checksums.txt.sigstore.json",
		"multiple.intoto.jsonl",
		"nox-plugin-red-team_0.7.0_darwin_arm64.tar.gz.sbom.json",
	}
	for _, s := range match {
		if artifactRe.FindStringSubmatch(s) == nil {
			t.Errorf("%q should be recognised as a platform artifact", s)
		}
	}
	for _, s := range reject {
		if artifactRe.FindStringSubmatch(s) != nil {
			t.Errorf("%q must NOT be treated as a platform artifact", s)
		}
	}
}

func TestArtifactReCapturesOSAndArch(t *testing.T) {
	m := artifactRe.FindStringSubmatch("nox-plugin-k8s-runtime_0.7.0_linux_arm64.tar.gz")
	if m == nil {
		t.Fatal("expected a match")
	}
	if m[1] != "linux" || m[2] != "arm64" {
		t.Errorf("os/arch = %q/%q, want linux/arm64", m[1], m[2])
	}
}
