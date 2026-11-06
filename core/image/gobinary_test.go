package image

import (
	"context"
	"debug/buildinfo"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// goExecutable builds testdata/gobin, a Go executable that links a module,
// and returns it with the build info buildinfo.ReadFile reads from it: the
// oracle the streaming reader is held to.
func goExecutable(t *testing.T) (body string, want *buildinfo.BuildInfo) {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "gobin")
	cmd := exec.Command("go", "build", "-o", exe, "./testdata/gobin")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the fixture: %v\n%s", err, out)
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	bi, err := buildinfo.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), bi
}

// A Go executable inside an image names its toolchain (stdlib at an exact
// version) and every module it linked. Read from the layer stream it gives
// the same answer debug/buildinfo gives reading the file.
func TestGoExecutableInALayerIsRead(t *testing.T) {
	body, bi := goExecutable(t)
	reg := newRegistry(t)
	digest := reg.image(t, layer(t, file{name: "etc/os-release", body: alpineRelease},
		file{name: "usr/local/bin/tool", body: body, exec: true}))
	got, err := reg.client(t).Contents(context.Background(), "golang", digest)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]Package{}
	for _, p := range got.Packages {
		if p.Ecosystem == "go" {
			have[p.Name+"@"+p.Version] = p
		}
	}
	std := "stdlib@" + strings.TrimPrefix(strings.Fields(bi.GoVersion)[0], "go")
	if p, ok := have[std]; !ok || p.Path != "usr/local/bin/tool" {
		t.Errorf("no %s from usr/local/bin/tool in %v", std, keys(have))
	}
	deps := 0
	for _, d := range bi.Deps {
		if d.Replace == nil && d.Version != "" {
			deps++
			if _, ok := have[d.Path+"@"+d.Version]; !ok {
				t.Errorf("module %s@%s that buildinfo reads is missing", d.Path, d.Version)
			}
		}
	}
	if deps == 0 {
		t.Fatal("the oracle binary lists no modules; the test proves nothing")
	}
}

// A binary a later layer deletes, or overwrites with a file nox does not read,
// is not in the image.
func TestGoExecutableRemovedByALaterLayerIsGone(t *testing.T) {
	body, _ := goExecutable(t)
	for name, top := range map[string]file{
		"whiteout":  {name: "usr/local/bin/tool", whiteout: true},
		"overwrite": {name: "usr/local/bin/tool", body: "#!/bin/sh\necho replaced\n", exec: true},
	} {
		t.Run(name, func(t *testing.T) {
			reg := newRegistry(t)
			digest := reg.image(t, layer(t, file{name: "etc/os-release", body: alpineRelease},
				file{name: "usr/local/bin/tool", body: body, exec: true}), layer(t, top))
			got, err := reg.client(t).Contents(context.Background(), "golang", digest)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range got.Packages {
				if p.Ecosystem == "go" {
					t.Fatalf("%s: a removed binary still reported %s@%s", name, p.Name, p.Version)
				}
			}
		})
	}
}

// A file that is not executable is not probed, whatever it contains.
func TestNonExecutableFileIsNotProbed(t *testing.T) {
	body, _ := goExecutable(t)
	reg := newRegistry(t)
	digest := reg.image(t, layer(t, file{name: "etc/os-release", body: alpineRelease},
		file{name: "srv/data.bin", body: body}))
	got, err := reg.client(t).Contents(context.Background(), "golang", digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got.Packages {
		if p.Ecosystem == "go" {
			t.Fatalf("a non-executable file was read as a Go binary: %+v", p)
		}
	}
}

func keys(m map[string]Package) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
