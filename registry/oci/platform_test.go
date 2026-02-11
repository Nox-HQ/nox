package oci

import (
	"errors"
	"runtime"
	"testing"

	"github.com/nox-hq/nox/registry"
)

func TestSelectArtifactFor(t *testing.T) {
	artifacts := []registry.PlatformArtifact{
		{OS: "darwin", Arch: "amd64", URL: "https://example.com/darwin-amd64.tar.gz", Digest: "sha256:aaa"},
		{OS: "darwin", Arch: "arm64", URL: "https://example.com/darwin-arm64.tar.gz", Digest: "sha256:bbb"},
		{OS: "linux", Arch: "amd64", URL: "https://example.com/linux-amd64.tar.gz", Digest: "sha256:ccc"},
		{OS: "linux", Arch: "arm64", URL: "https://example.com/linux-arm64.tar.gz", Digest: "sha256:ddd"},
		{OS: "windows", Arch: "amd64", URL: "https://example.com/windows-amd64.zip", Digest: "sha256:eee"},
	}

	tests := []struct {
		name    string
		goos    string
		goarch  string
		wantURL string
		wantErr error
	}{
		{
			name:    "darwin/amd64",
			goos:    "darwin",
			goarch:  "amd64",
			wantURL: "https://example.com/darwin-amd64.tar.gz",
		},
		{
			name:    "darwin/arm64",
			goos:    "darwin",
			goarch:  "arm64",
			wantURL: "https://example.com/darwin-arm64.tar.gz",
		},
		{
			name:    "linux/amd64",
			goos:    "linux",
			goarch:  "amd64",
			wantURL: "https://example.com/linux-amd64.tar.gz",
		},
		{
			name:    "linux/arm64",
			goos:    "linux",
			goarch:  "arm64",
			wantURL: "https://example.com/linux-arm64.tar.gz",
		},
		{
			name:    "windows/amd64",
			goos:    "windows",
			goarch:  "amd64",
			wantURL: "https://example.com/windows-amd64.zip",
		},
		{
			name:    "no match freebsd",
			goos:    "freebsd",
			goarch:  "amd64",
			wantErr: ErrNoPlatformMatch,
		},
		{
			name:    "no match wrong arch",
			goos:    "darwin",
			goarch:  "386",
			wantErr: ErrNoPlatformMatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SelectArtifactFor(artifacts, tt.goos, tt.goarch)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", got.URL, tt.wantURL)
			}
		})
	}
}

func TestSelectArtifactForEmptyList(t *testing.T) {
	_, err := SelectArtifactFor(nil, "linux", "amd64")
	if !errors.Is(err, ErrNoPlatformMatch) {
		t.Errorf("error = %v, want %v", err, ErrNoPlatformMatch)
	}
}

func TestSelectArtifactForReturnsFirstMatch(t *testing.T) {
	artifacts := []registry.PlatformArtifact{
		{OS: "linux", Arch: "amd64", URL: "first", Digest: "sha256:111"},
		{OS: "linux", Arch: "amd64", URL: "second", Digest: "sha256:222"},
	}

	got, err := SelectArtifactFor(artifacts, "linux", "amd64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.URL != "first" {
		t.Errorf("URL = %q, want %q (first match)", got.URL, "first")
	}
}

// TestSelectArtifact tests the runtime-platform-aware SelectArtifact function.
func TestSelectArtifact(t *testing.T) {
	// Build an artifact list that includes the current runtime OS/arch.
	artifacts := []registry.PlatformArtifact{
		{OS: "freebsd", Arch: "riscv64", URL: "https://example.com/freebsd-riscv64.tar.gz", Digest: "sha256:aaa"},
		{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "https://example.com/current-platform.tar.gz", Digest: "sha256:bbb"},
	}

	got, err := SelectArtifact(artifacts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.URL != "https://example.com/current-platform.tar.gz" {
		t.Errorf("URL = %q, want current-platform URL", got.URL)
	}
	if got.OS != runtime.GOOS {
		t.Errorf("OS = %q, want %q", got.OS, runtime.GOOS)
	}
	if got.Arch != runtime.GOARCH {
		t.Errorf("Arch = %q, want %q", got.Arch, runtime.GOARCH)
	}
}

// TestSelectArtifactNoMatch tests SelectArtifact when no artifact matches.
func TestSelectArtifactNoMatch(t *testing.T) {
	artifacts := []registry.PlatformArtifact{
		{OS: "plan9", Arch: "mips", URL: "https://example.com/plan9-mips.tar.gz", Digest: "sha256:aaa"},
	}

	_, err := SelectArtifact(artifacts)
	if !errors.Is(err, ErrNoPlatformMatch) {
		t.Errorf("error = %v, want %v", err, ErrNoPlatformMatch)
	}
}

// TestSelectArtifactEmptyList tests SelectArtifact with an empty artifact list.
func TestSelectArtifactEmptyList(t *testing.T) {
	_, err := SelectArtifact(nil)
	if !errors.Is(err, ErrNoPlatformMatch) {
		t.Errorf("error = %v, want %v", err, ErrNoPlatformMatch)
	}
}
