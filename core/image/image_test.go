package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

type file struct {
	name, body string
	whiteout   bool // write the name as a .wh. entry
	opaque     bool // write an opaque-directory marker for name
	exec       bool // mode 0755
}

func layer(t *testing.T, files ...file) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		name := f.name
		switch {
		case f.whiteout:
			dir, base := splitPath(name)
			name = dir + ".wh." + base
		case f.opaque:
			name = strings.TrimSuffix(name, "/") + "/.wh..wh..opq"
		}
		mode := int64(0o644)
		if f.exec {
			mode = 0o755
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(f.body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func splitPath(p string) (dir, base string) {
	i := strings.LastIndex(p, "/")
	return p[:i+1], p[i+1:]
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// registry serves one repository's manifests and blobs the way Docker Hub
// does: every /v2 request without a bearer token is answered 401 with a
// WWW-Authenticate challenge naming the token endpoint.
type registry struct {
	srv       *httptest.Server
	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string][]byte // by digest
	types     map[string]string
	requests  []string
	tamper    string // a blob digest to serve corrupted
}

func newRegistry(t *testing.T) *registry {
	t.Helper()
	r := &registry{blobs: map[string][]byte{}, manifests: map[string][]byte{}, types: map[string]string{}}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *registry) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req.URL.Path)
	if req.URL.Path == "/token" {
		if req.URL.Query().Get("scope") != "repository:library/golang:pull" {
			http.Error(w, "bad scope "+req.URL.Query().Get("scope"), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "anon"})
		return
	}
	if req.Header.Get("Authorization") != "Bearer anon" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="test",scope="repository:library/golang:pull"`, r.srv.URL))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	const prefix = "/v2/library/golang/"
	switch {
	case strings.HasPrefix(req.URL.Path, prefix+"manifests/"):
		d := strings.TrimPrefix(req.URL.Path, prefix+"manifests/")
		body, ok := r.manifests[d]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", r.types[d])
		_, _ = w.Write(body)
	case strings.HasPrefix(req.URL.Path, prefix+"blobs/"):
		d := strings.TrimPrefix(req.URL.Path, prefix+"blobs/")
		body, ok := r.blobs[d]
		if !ok {
			http.NotFound(w, req)
			return
		}
		if d == r.tamper {
			body = append([]byte{}, body...)
			body[len(body)/2] ^= 0xff
		}
		_, _ = w.Write(body)
	default:
		http.NotFound(w, req)
	}
}

func (r *registry) addBlob(b []byte) string {
	d := digestOf(b)
	r.blobs[d] = b
	return d
}

// image publishes an image index whose linux/amd64 entry has the layers, and
// returns the index digest, which is what a pinned FROM names.
func (r *registry) image(t *testing.T, layers ...[]byte) string {
	t.Helper()
	cfg := r.addBlob([]byte(`{"architecture":"amd64","os":"linux"}`))
	var descs []map[string]any
	for _, l := range layers {
		descs = append(descs, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": r.addBlob(l), "size": len(l)})
	}
	manifest, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg, "size": 10},
		"layers": descs,
	})
	md := digestOf(manifest)
	r.manifests[md], r.types[md] = manifest, "application/vnd.oci.image.manifest.v1+json"
	arm, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"digest": cfg, "size": 10}, "layers": []any{}})
	ad := digestOf(arm)
	r.manifests[ad], r.types[ad] = arm, "application/vnd.oci.image.manifest.v1+json"
	index, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []map[string]any{
			{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": ad, "size": len(arm), "platform": map[string]string{"os": "linux", "architecture": "arm64"}},
			{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": md, "size": len(manifest), "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
		},
	})
	id := digestOf(index)
	r.manifests[id], r.types[id] = index, "application/vnd.oci.image.index.v1+json"
	return id
}

func (r *registry) client(t *testing.T) *Client {
	t.Helper()
	return &Client{HTTP: r.srv.Client(), CacheDir: t.TempDir(), registryOverride: r.srv.URL}
}

func pkgs(c Contents) []string {
	var out []string
	for _, p := range c.Packages {
		out = append(out, p.Ecosystem+" "+p.Name+" "+p.Version)
	}
	sort.Strings(out)
	return out
}

const alpineRelease = "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.22.1\n"

// apk's installed database names each package (P), its version (V) and the
// source package it was built from (o). OSV's Alpine advisories name source
// packages, so the source is what is reported: libssl3 and libcrypto3 are
// both openssl.
const apkInstalled = `C:Q1abc=
P:musl
V:1.2.5-r10
o:musl

C:Q1def=
P:libcrypto3
V:3.5.1-r0
o:openssl

C:Q1ghi=
P:libssl3
V:3.5.1-r0
o:openssl
`

// A pinned image is fetched by digest through the token flow, its linux/amd64
// manifest chosen from the index, its layers applied in order with whiteouts,
// and what is installed read without running anything.
func TestAlpineImageContents(t *testing.T) {
	reg := newRegistry(t)
	base := layer(t, file{name: "etc/os-release", body: alpineRelease}, file{name: "lib/apk/db/installed", body: apkInstalled},
		file{name: "usr/local/go/VERSION", body: "go1.26.3\ntime 2026-10-01T00:00:00Z\n"})
	digest := reg.image(t, base)

	got, err := reg.client(t).Contents(context.Background(), "golang", digest)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpine:v3.22 musl 1.2.5-r10", "alpine:v3.22 openssl 3.5.1-r0", "go stdlib 1.26.3"}
	if g := pkgs(got); strings.Join(g, "|") != strings.Join(want, "|") {
		t.Errorf("packages %v, want %v", g, want)
	}
	if got.Distro != "alpine:v3.22" {
		t.Errorf("distro %q", got.Distro)
	}
}

const debianRelease = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n"

// dpkg's status lists installed and removed packages; only "install ok
// installed" counts. Source, with its own version in parentheses when it
// differs, is what OSV's Debian advisories name.
const dpkgStatus = `Package: libssl3
Status: install ok installed
Source: openssl
Version: 3.0.15-1~deb12u1

Package: libc6
Status: install ok installed
Source: glibc
Version: 2.36-9+deb12u7

Package: zlib1g
Status: install ok installed
Source: zlib (1:1.2.13.dfsg-1)
Version: 1:1.2.13.dfsg-1

Package: removed-thing
Status: deinstall ok config-files
Version: 1.0
`

func TestDebianImageContentsAndWhiteouts(t *testing.T) {
	reg := newRegistry(t)
	base := layer(t, file{name: "etc/os-release", body: debianRelease}, file{name: "var/lib/dpkg/status", body: dpkgStatus},
		file{name: "usr/local/go/VERSION", body: "go1.25.0\n"})
	// A later layer deletes the Go toolchain: it must not be reported.
	top := layer(t, file{name: "usr/local/go/VERSION", whiteout: true})
	digest := reg.image(t, base, top)

	got, err := reg.client(t).Contents(context.Background(), "golang", digest)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"debian:12 glibc 2.36-9+deb12u7", "debian:12 openssl 3.0.15-1~deb12u1", "debian:12 zlib 1:1.2.13.dfsg-1"}
	if g := pkgs(got); strings.Join(g, "|") != strings.Join(want, "|") {
		t.Errorf("packages %v, want %v", g, want)
	}
}

// Distroless images keep one status file per package under status.d.
func TestDistrolessStatusD(t *testing.T) {
	reg := newRegistry(t)
	base := layer(t, file{name: "etc/os-release", body: debianRelease},
		file{name: "var/lib/dpkg/status.d/libssl3", body: "Package: libssl3\nSource: openssl\nVersion: 3.0.15-1~deb12u1\n"},
		file{name: "var/lib/dpkg/status.d/tzdata", body: "Package: tzdata\nVersion: 2025b-0+deb12u1\n"})
	got, err := reg.client(t).Contents(context.Background(), "golang", reg.image(t, base))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"debian:12 openssl 3.0.15-1~deb12u1", "debian:12 tzdata 2025b-0+deb12u1"}
	if g := pkgs(got); strings.Join(g, "|") != strings.Join(want, "|") {
		t.Errorf("packages %v, want %v", g, want)
	}
}

// An opaque directory in a later layer hides everything below it: a
// distroless entry the lower layer had, and the upper one does not re-add, is
// gone. (Re-adding the same file would replace it opaque or not, and test
// nothing.)
func TestOpaqueDirectoryHidesLowerLayers(t *testing.T) {
	reg := newRegistry(t)
	base := layer(t, file{name: "etc/os-release", body: debianRelease},
		file{name: "var/lib/dpkg/status.d/oldpkg", body: "Package: oldpkg\nVersion: 1.0-1\n"})
	top := layer(t, file{name: "var/lib/dpkg/status.d/", opaque: true},
		file{name: "var/lib/dpkg/status.d/tzdata", body: "Package: tzdata\nVersion: 2025b-0+deb12u1\n"})
	got, err := reg.client(t).Contents(context.Background(), "golang", reg.image(t, base, top))
	if err != nil {
		t.Fatal(err)
	}
	if g := pkgs(got); strings.Join(g, "|") != "debian:12 tzdata 2025b-0+deb12u1" {
		t.Errorf("packages %v, want only what the opaque layer holds", g)
	}
}

// A blob whose content does not match its digest fails the image: a partly
// read image would understate what it holds.
func TestTamperedLayerIsRefused(t *testing.T) {
	reg := newRegistry(t)
	base := layer(t, file{name: "etc/os-release", body: alpineRelease}, file{name: "lib/apk/db/installed", body: apkInstalled})
	digest := reg.image(t, base)
	reg.tamper = digestOf(base)
	if _, err := reg.client(t).Contents(context.Background(), "golang", digest); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tampered layer: %v", err)
	}
}

// Blobs are cached by digest: a second read of the same image, offline, comes
// from the cache and makes no request.
func TestSecondReadComesFromTheCache(t *testing.T) {
	reg := newRegistry(t)
	digest := reg.image(t, layer(t, file{name: "etc/os-release", body: alpineRelease}, file{name: "lib/apk/db/installed", body: apkInstalled}))
	c := reg.client(t)
	first, err := c.Contents(context.Background(), "golang", digest)
	if err != nil {
		t.Fatal(err)
	}
	reg.srv.Close()
	c.Offline = true
	second, err := c.Contents(context.Background(), "golang", digest)
	if err != nil {
		t.Fatalf("offline read from the cache: %v", err)
	}
	if strings.Join(pkgs(first), "|") != strings.Join(pkgs(second), "|") {
		t.Errorf("cache gave %v, network gave %v", pkgs(second), pkgs(first))
	}
}

// An image larger than the budget is refused rather than half read.
func TestImageOverBudgetIsRefused(t *testing.T) {
	reg := newRegistry(t)
	big := layer(t, file{name: "etc/os-release", body: alpineRelease}, file{name: "blob", body: strings.Repeat("x", 64<<10)})
	c := reg.client(t)
	c.MaxBytes = 1 << 10
	if _, err := c.Contents(context.Background(), "golang", reg.image(t, big)); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("over budget: %v", err)
	}
}

// References name Docker Hub's library and default registry the way docker
// does.
func TestParseRef(t *testing.T) {
	for in, want := range map[string]Ref{
		"golang":                     {Registry: "registry-1.docker.io", Repository: "library/golang"},
		"golang:1.26-alpine":         {Registry: "registry-1.docker.io", Repository: "library/golang"},
		"bitnami/redis:7":            {Registry: "registry-1.docker.io", Repository: "bitnami/redis"},
		"ghcr.io/nox-hq/nox:1":       {Registry: "ghcr.io", Repository: "nox-hq/nox"},
		"localhost:5000/team/app:v2": {Registry: "localhost:5000", Repository: "team/app"},
		"docker.io/library/node":     {Registry: "registry-1.docker.io", Repository: "library/node"},
	} {
		if got := ParseRef(in); got != want {
			t.Errorf("ParseRef(%q) = %+v, want %+v", in, got, want)
		}
	}
}

// Ubuntu's advisories are published per support stream; an image's
// os-release says which: an LTS release is "24.04:LTS", any other the
// release alone.
func TestUbuntuStreamComesFromOSRelease(t *testing.T) {
	for want, release := range map[string]string{
		"ubuntu:24.04:LTS": "NAME=\"Ubuntu\"\nVERSION=\"24.04.3 LTS (Noble Numbat)\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n",
		"ubuntu:25.10":     "NAME=\"Ubuntu\"\nVERSION=\"25.10 (Questing Quokka)\"\nID=ubuntu\nVERSION_ID=\"25.10\"\n",
	} {
		reg := newRegistry(t)
		digest := reg.image(t, layer(t, file{name: "etc/os-release", body: release},
			file{name: "var/lib/dpkg/status", body: "Package: libssl3t64\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.13-0ubuntu3.1\n"}))
		got, err := reg.client(t).Contents(context.Background(), "golang", digest)
		if err != nil {
			t.Fatal(err)
		}
		if got.Distro != want || strings.Join(pkgs(got), "|") != want+" openssl 3.0.13-0ubuntu3.1" {
			t.Errorf("distro %q packages %v; want %s", got.Distro, pkgs(got), want)
		}
	}
}
