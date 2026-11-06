package image

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Real images, pinned by digest so the answer cannot drift: reading them is
// the measurement the design note (docs/design/container-image-advisories.md)
// asks for before image checking is on by default. Opt-in, because it reaches
// Docker Hub and gcr.io: NOX_IMAGE_LIVE=1 go test ./core/image -run Live -v
func TestLiveImages(t *testing.T) {
	if os.Getenv("NOX_IMAGE_LIVE") == "" {
		t.Skip("set NOX_IMAGE_LIVE=1 to read real images from their registries")
	}
	c := &Client{HTTP: &http.Client{Timeout: 5 * time.Minute}, CacheDir: t.TempDir()}
	for _, tc := range []struct {
		name, digest, distro string
		minPkgs              int
		mustHave             []string // "ecosystem name" prefixes
	}{
		// node:*-slim has no Debian openssl: Node bundles its own OpenSSL in
		// the node binary, which no package database lists. Reading the
		// runtimes and binaries inside images is a later step.
		{"golang:1.26-alpine", "sha256:df23b876380eb556f22bbba2fa57493e8684fc4fcabf06399fbfb65359978d28", "alpine:v3.", 10, []string{"go stdlib 1.26.", "alpine:v3.", "openssl"}},
		{"node:22-bookworm-slim", "sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d", "debian:12", 50, []string{"debian:12 glibc ", "debian:12 gnutls28 "}},
		{"gcr.io/distroless/static-debian12", "sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab", "debian:12", 3, []string{"debian:12 tzdata "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			got, err := c.Contents(context.Background(), tc.name, tc.digest)
			if err != nil {
				t.Fatal(err)
			}
			all := strings.Join(pkgs(got), "\n")
			t.Logf("%s: distro %s, %d packages in %s", tc.name, got.Distro, len(got.Packages), time.Since(start).Round(time.Millisecond))
			if !strings.HasPrefix(got.Distro, tc.distro) || len(got.Packages) < tc.minPkgs {
				t.Errorf("distro %q, %d packages; want %s*, at least %d", got.Distro, len(got.Packages), tc.distro, tc.minPkgs)
			}
			for _, want := range tc.mustHave {
				if !strings.Contains(all, want) {
					t.Errorf("no package matching %q in:\n%s", want, all)
				}
			}
		})
	}
}
