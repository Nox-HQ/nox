package oci

import (
	"errors"
	"testing"

	"github.com/felixgeelhaar/hardline/registry"
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
