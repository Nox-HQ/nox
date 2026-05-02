package main

import (
	"testing"

	"github.com/nox-hq/nox/registry"
)

func TestParseChecksumsFile(t *testing.T) {
	body := []byte(`
abc123def456abc123def456abc123def456abc123def456abc123def456abc1  nox-plugin-foo_0.1.0_linux_amd64.tar.gz
0011223344556677889900112233445566778899001122334455667788990011  nox-plugin-foo_0.1.0_darwin_arm64.tar.gz
short  irrelevant
`)
	got := parseChecksumsFile(body)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d (%v)", len(got), got)
	}
	if got["nox-plugin-foo_0.1.0_linux_amd64.tar.gz"] != "abc123def456abc123def456abc123def456abc123def456abc123def456abc1" {
		t.Errorf("linux digest mismatch: %v", got)
	}
}

func TestStampEntryDigests_NoChecksumsAvailable(t *testing.T) {
	// Override stdHTTPGet to simulate 404.
	prev := stdHTTPGet
	t.Cleanup(func() { stdHTTPGet = prev })
	stdHTTPGet = mockHTTP(404, "")

	entry := registry.PluginEntry{
		Versions: []registry.VersionEntry{{
			Version: "0.1.0",
			Artifacts: []registry.PlatformArtifact{{
				OS: "linux", Arch: "amd64",
				URL:    "https://github.com/nox-hq/nox-plugin-foo/releases/download/v0.1.0/nox-plugin-foo_0.1.0_linux_amd64.tar.gz",
				Digest: "sha256:tbd",
			}},
		}},
	}
	if err := stampEntryDigests(&entry, "nox-hq/nox-plugin-foo", "0.1.0"); err == nil {
		t.Error("expected error on 404")
	}
}

func TestStampEntryDigests_RewritesPlaceholder(t *testing.T) {
	prev := stdHTTPGet
	t.Cleanup(func() { stdHTTPGet = prev })
	stdHTTPGet = mockHTTP(200,
		"deadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233  nox-plugin-foo_0.1.0_linux_amd64.tar.gz\n")

	entry := registry.PluginEntry{
		Versions: []registry.VersionEntry{{
			Version: "0.1.0",
			Artifacts: []registry.PlatformArtifact{{
				OS: "linux", Arch: "amd64",
				URL:    "https://github.com/nox-hq/nox-plugin-foo/releases/download/v0.1.0/nox-plugin-foo_0.1.0_linux_amd64.tar.gz",
				Digest: "sha256:tbd",
			}},
		}},
	}
	if err := stampEntryDigests(&entry, "nox-hq/nox-plugin-foo", "0.1.0"); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	got := entry.Versions[0].Artifacts[0].Digest
	want := "sha256:deadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233"
	if got != want {
		t.Errorf("digest got %q want %q", got, want)
	}
}
