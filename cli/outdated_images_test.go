package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	digestA = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digestC = "sha256:" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// Only a FROM naming a registry image is a base image. A stage reference, the
// empty image and an ARG-substituted name are not something a registry can be
// asked about.
func TestBaseImageRefs(t *testing.T) {
	src := "ARG GO=1.27\n" +
		"FROM --platform=$BUILDPLATFORM golang:1.27-alpine@" + digestA + " AS builder\n" +
		"FROM builder AS test\n" +
		"FROM scratch\n" +
		"FROM ${BASE}\n" +
		"from gcr.io/distroless/static-debian12:nonroot@" + digestB + "\n" +
		"FROM alpine:3.20\n"
	var got []string
	for _, r := range baseImageRefs(src) {
		got = append(got, r.image+"|"+r.tag+"|"+r.digest)
	}
	want := []string{
		"golang|1.27-alpine|" + digestA,
		"gcr.io/distroless/static-debian12|nonroot|" + digestB,
		"alpine|3.20|",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestImageRegistryAndRepository(t *testing.T) {
	for _, tc := range []struct{ image, host, repo string }{
		{"golang", "docker.io", "library/golang"},
		{"bitnami/redis", "docker.io", "bitnami/redis"},
		{"gcr.io/distroless/static-debian12", "gcr.io", "distroless/static-debian12"},
		{"ghcr.io/nox-hq/nox", "ghcr.io", "nox-hq/nox"},
		{"localhost:5000/tool", "localhost:5000", "tool"},
	} {
		host, repo := imageLocation(tc.image)
		if host != tc.host || repo != tc.repo {
			t.Errorf("%s: got %s %s, want %s %s", tc.image, host, repo, tc.host, tc.repo)
		}
	}
}

// A tag moves only to one of the same shape: 1.27-alpine to 1.28-alpine, not
// to 1.28.1-alpine (a different granularity), 1.28-bookworm (a different
// base), 1.29rc1-alpine (a prerelease) or latest. A major move is held.
func TestNewerTagOfTheSameShape(t *testing.T) {
	tags := []string{"1.27-alpine", "1.28-alpine", "1.28.1-alpine", "1.28-bookworm",
		"1.29rc1-alpine", "2.0-alpine", "latest", "1.9-alpine"}
	if got, major := newerTag("1.27-alpine", tags, false); got != "1.28-alpine" || !major {
		t.Errorf("got %q (major held %v), want 1.28-alpine with a major held", got, major)
	}
	if got, _ := newerTag("1.27-alpine", tags, true); got != "2.0-alpine" {
		t.Errorf("with majors: got %q, want 2.0-alpine", got)
	}
	if got, _ := newerTag("nonroot", tags, true); got != "" {
		t.Errorf("a non-numeric tag has no newer version; got %q", got)
	}
}

// fakeRegistry speaks enough of the OCI distribution API to be asked: an
// anonymous bearer challenge, a token endpoint, manifest HEADs that return a
// digest, and a tag list.
func fakeRegistry(t *testing.T, digests map[string]string, tags []string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = w.Write([]byte(`{"token":"t0k"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer t0k" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="fake",scope="repository:library/golang:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/tags/list"):
			_, _ = w.Write([]byte(`{"tags":["` + strings.Join(tags, `","`) + `"]}`))
		case strings.Contains(r.URL.Path, "/manifests/"):
			ref := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			d, ok := digests[ref]
			if !ok || !strings.Contains(r.Header.Get("Accept"), "application/vnd.oci.image.index.v1+json") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Docker-Content-Digest", d)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The whole pass on one Dockerfile: the builder's tag moves within its line
// and takes the new tag's digest; a digest-pinned tag that did not move gets
// its current digest; nothing else in the file changes.
func TestBaseImagesPlanAndApply(t *testing.T) {
	srv := fakeRegistry(t, map[string]string{
		"1.28-alpine": digestB,
		"3.20":        digestC,
	}, []string{"1.27-alpine", "1.28-alpine", "3.20"})
	reg := &imageRegistry{client: srv.Client(), baseFor: func(string) string { return srv.URL }}

	dir := t.TempDir()
	df := "FROM golang:1.27-alpine@" + digestA + " AS builder\nRUN go build\n" +
		"FROM alpine:3.20@" + digestA + "\nCOPY --from=builder /x /x\n"
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(df), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, degraded := planImageCurrency(dir, false, reg)
	if len(degraded) != 0 {
		t.Fatalf("degraded: %v", degraded)
	}
	if len(plan.actions) != 2 {
		t.Fatalf("want 2 actions, got %+v", plan.actions)
	}
	for _, a := range plan.actions {
		a.manifest = "Dockerfile"
		if err := applyUpgrade(dir, a); err != nil {
			t.Fatalf("apply %s: %v", a.pkg, err)
		}
	}
	got, _ := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	want := "FROM golang:1.28-alpine@" + digestB + " AS builder\nRUN go build\n" +
		"FROM alpine:3.20@" + digestC + "\nCOPY --from=builder /x /x\n"
	if string(got) != want {
		t.Errorf("Dockerfile after apply:\n%s\nwant:\n%s", got, want)
	}
}

// A registry that cannot be asked is reported, never read as "current".
func TestAnUnreachableRegistryIsDegraded(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM golang:1.27-alpine@"+digestA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := &imageRegistry{client: http.DefaultClient, baseFor: func(string) string { return "http://127.0.0.1:1" }}
	plan, degraded := planImageCurrency(dir, false, reg)
	if len(plan.actions) != 0 || len(degraded) == 0 {
		t.Errorf("want no actions and a degradation; got %+v / %v", plan.actions, degraded)
	}
}
