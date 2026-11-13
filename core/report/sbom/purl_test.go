package sbom

import (
	"testing"

	"github.com/nox-hq/nox/core/analyzers/deps"
)

// Every ecosystem nox inventories gets the purl the purl spec defines for it.
// Without one, an SBOM consumer cannot tell which ecosystem a component is
// from: an image's Debian glibc and a Go module named glibc look alike.
func TestBuildPURLCoversInventoriedEcosystems(t *testing.T) {
	for _, c := range []struct {
		pkg  deps.Package
		want string
	}{
		{deps.Package{Name: "musl", Version: "1.2.5-r10", Ecosystem: "alpine:v3.22"},
			"pkg:apk/alpine/musl@1.2.5-r10?arch=source&distro=alpine-3.22"},
		{deps.Package{Name: "glibc", Version: "2.36-9+deb12u14", Ecosystem: "debian:12"},
			"pkg:deb/debian/glibc@2.36-9%2Bdeb12u14?arch=source&distro=debian-12"},
		{deps.Package{Name: "attr", Version: "1:2.5.2-1ubuntu0.1", Ecosystem: "ubuntu:24.04:LTS"},
			"pkg:deb/ubuntu/attr@1:2.5.2-1ubuntu0.1?arch=source&distro=ubuntu-24.04"},
		// rpm: binary package, epoch as a qualifier, not in the version.
		{deps.Package{Name: "openssl-libs", Version: "1:3.0.1-41.el9_0", Ecosystem: "almalinux:9"},
			"pkg:rpm/almalinux/openssl-libs@3.0.1-41.el9_0?distro=almalinux-9&epoch=1"},
		{deps.Package{Name: "glibc", Version: "2.34-100.el9_4.2", Ecosystem: "rocky:9"},
			"pkg:rpm/rocky/glibc@2.34-100.el9_4.2?distro=rocky-9"},
		{deps.Package{Name: "golang", Version: "sha256:df23b876380eb556f22bbba2fa57493e8684fc4fcabf06399fbfb65359978d28", Ecosystem: "docker"},
			"pkg:docker/library/golang@sha256:df23b876380eb556f22bbba2fa57493e8684fc4fcabf06399fbfb65359978d28"},
		{deps.Package{Name: "ghcr.io/nox-hq/nox", Version: "1.61.0", Ecosystem: "docker"},
			"pkg:docker/nox-hq/nox@1.61.0?repository_url=ghcr.io"},
		{deps.Package{Name: "monolog/monolog", Version: "3.5.0", Ecosystem: "composer"}, "pkg:composer/monolog/monolog@3.5.0"},
		{deps.Package{Name: "http", Version: "1.2.0", Ecosystem: "pub"}, "pkg:pub/http@1.2.0"},
		{deps.Package{Name: "phoenix", Version: "1.7.10", Ecosystem: "hex"}, "pkg:hex/phoenix@1.7.10"},
		{deps.Package{Name: "github.com/vapor/vapor", Version: "4.89.0", Ecosystem: "swift"}, "pkg:swift/github.com/vapor/vapor@4.89.0"},
		// OpenSSL linked statically into an image's binary.
		{deps.Package{Name: "openssl", Version: "3.5.9", Ecosystem: "openssl"}, "pkg:generic/openssl@3.5.9"},
		// Unchanged forms.
		{deps.Package{Name: "golang.org/x/net", Version: "v0.30.0", Ecosystem: "go"}, "pkg:golang/golang.org/x/net@v0.30.0"},
		{deps.Package{Name: "org.apache:commons", Version: "1.0", Ecosystem: "maven"}, "pkg:maven/org.apache/commons@1.0"},
	} {
		if got := buildPURL(c.pkg); got != c.want {
			t.Errorf("buildPURL(%s %s@%s)\n got %q\nwant %q", c.pkg.Ecosystem, c.pkg.Name, c.pkg.Version, got, c.want)
		}
	}
}
