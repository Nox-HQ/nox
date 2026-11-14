package deps

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/vulnsource"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/image"
)

func TestBuildOnlyStages(t *testing.T) {
	const a = "golang:1.27-alpine@sha256:aaaa"
	const b = "gcr.io/distroless/static@sha256:bbbb"
	tests := []struct {
		name       string
		dockerfile string
		want       []string // index-aligned with ParseDockerfile's images
	}{
		{
			name:       "single stage ships",
			dockerfile: "FROM " + a + "\nRUN go build\n",
			want:       []string{""},
		},
		{
			name: "nox's own: binary copied onto distroless",
			dockerfile: "FROM " + a + " AS builder\nWORKDIR /build\nRUN go build -o nox\n" +
				"FROM " + b + "\nCOPY --from=builder --chown=nonroot:nonroot /build/nox /usr/local/bin/nox\n",
			want: []string{"builder", ""},
		},
		{
			name: "copied by stage index",
			dockerfile: "FROM " + a + "\nRUN go build -o /out/app\n" +
				"FROM " + b + "\nCOPY --from=0 /out/app /app\n",
			want: []string{"0", ""},
		},
		{
			name: "final stage built on the builder ships it",
			dockerfile: "FROM " + a + " AS base\nRUN apk add curl\n" +
				"FROM base AS final\nCMD [\"curl\"]\n",
			want: []string{""},
		},
		{
			name: "copying system files ships the stage",
			dockerfile: "FROM " + a + " AS builder\n" +
				"FROM " + b + "\nCOPY --from=builder /usr/lib/libz.so.1 /usr/lib/\n",
			want: []string{"", ""},
		},
		{
			name: "relative source is read from the stage root",
			dockerfile: "FROM " + a + " AS builder\n" +
				"FROM " + b + "\nCOPY --from=builder lib/libz.so.1 /lib/\n",
			want: []string{"", ""},
		},
		{
			name: "copying the whole root ships the stage",
			dockerfile: "FROM " + a + " AS builder\n" +
				"FROM " + b + "\nCOPY --from=builder / /\n",
			want: []string{"", ""},
		},
		{
			name: "wildcard at the root ships the stage",
			dockerfile: "FROM " + a + " AS builder\n" +
				"FROM " + b + "\nCOPY --from=builder /* /\n",
			want: []string{"", ""},
		},
		{
			name: "JSON form and a continuation are read",
			dockerfile: "FROM " + a + " AS builder\n" +
				"FROM " + b + "\nCOPY --from=builder \\\n  [\"/build/app\", \"/etc/ssl/certs/ca.pem\", \"/dst/\"]\n",
			want: []string{"", ""},
		},
		{
			name: "a stage copied only by another build-only stage does not ship",
			dockerfile: "FROM " + a + " AS deps\nRUN apk add zlib\n" +
				"FROM " + a + " AS builder\nCOPY --from=deps /usr/lib /usr/lib\nRUN go build -o /app\n" +
				"FROM " + b + "\nCOPY --from=builder /app /app\n",
			want: []string{"deps", "builder", ""},
		},
		{
			name: "system files copied through a chain ship every link",
			dockerfile: "FROM " + a + " AS deps\n" +
				"FROM " + a + " AS builder\nCOPY --from=deps /usr/lib /usr/lib\n" +
				"FROM " + b + "\nCOPY --from=builder /usr/lib /usr/lib\n",
			want: []string{"", "", ""},
		},
		{
			name: "COPY --from a variable: everything counts as shipped",
			dockerfile: "ARG SRC=builder\nFROM " + a + " AS builder\n" +
				"FROM " + b + "\nCOPY --from=$SRC /app /app\n",
			want: []string{"", ""},
		},
		{
			name: "FROM a variable: everything counts as shipped",
			dockerfile: "ARG BASE\nFROM " + a + " AS builder\n" +
				"FROM ${BASE}\nCOPY --from=builder /app /app\n",
			want: []string{""},
		},
		{
			name: "COPY --from an external image is not a stage",
			dockerfile: "FROM " + a + " AS builder\n" +
				"FROM " + b + "\nCOPY --from=busybox:1.36 /bin/busybox /bin/\nCOPY --from=builder /app /app\n",
			want: []string{"builder", ""},
		},
		{
			name: "scratch final stage",
			dockerfile: "FROM " + a + " AS builder\nRUN go build -o /app\n" +
				"FROM scratch\nCOPY --from=builder /app /app\n",
			want: []string{"builder"},
		},
		{
			name: "a stage named like its image is skipped as ParseDockerfile skips it",
			dockerfile: "FROM golang AS golang\n" +
				"FROM " + b + "\nCOPY --from=golang /app /app\n",
			want: []string{""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			images, err := ParseDockerfile([]byte(tt.dockerfile))
			if err != nil {
				t.Fatal(err)
			}
			got := buildOnlyStages([]byte(tt.dockerfile))
			if len(got) != len(images) {
				t.Fatalf("buildOnlyStages returned %d entries for %d images: %q; the walks are no longer aligned",
					len(got), len(images), got)
			}
			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// The same advisory against the same package, once in a builder whose only
// export is a binary and once in the image that ships: the shipped one keeps
// its rating and gates; the builder's is recorded at info with the stage named
// and the rating kept in original_severity.
func TestBuildStageAdvisoryIsRecordedAtInfo(t *testing.T) {
	const builder = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const runtime = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	zlib := []image.Package{{Name: "zlib", Version: "1.3.2-r1", Ecosystem: "alpine:v3.24", Path: "lib/apk/db/installed"}}
	imgs := &fakeImages{contents: map[string]image.Contents{
		"golang:1.27-alpine@" + builder: {Distro: "alpine:v3.24", Packages: zlib},
		"alpine:3.24@" + runtime:        {Distro: "alpine:v3.24", Packages: zlib},
	}}
	rec := vulnsource.Record{
		ID:       "ALPINE-CVE-2099-0001",
		Severity: []vulnsource.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		Affected: []vulnsource.Affected{{
			Package: vulnsource.Package{Name: "zlib", Ecosystem: "Alpine:v3.24"},
			Ranges:  []vulnsource.Range{{Type: "ECOSYSTEM", Events: []vulnsource.Event{{Introduced: "0"}, {Fixed: "1.4-r0"}}}},
		}},
	}
	src := &stubSource{name: "stub", records: map[string][]vulnsource.Record{"zlib": {rec}}}

	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := "FROM golang:1.27-alpine@" + builder + " AS builder\nRUN go build -o /build/app\n" +
		"FROM alpine:3.24@" + runtime + "\nCOPY --from=builder /build/app /usr/local/bin/app\n"
	if err := os.WriteFile(df, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, fs, err := NewAnalyzer(WithSource(src), WithImages(imgs)).ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: "Dockerfile", AbsPath: df, Type: discovery.Container}})
	if err != nil {
		t.Fatal(err)
	}
	byLine := map[int]findings.Finding{}
	for _, f := range fs.Findings() {
		if f.RuleID == "VULN-001" && f.Metadata["package"] == "zlib" {
			byLine[f.Location.StartLine] = f
		}
	}
	built, ok := byLine[1]
	if !ok {
		t.Fatalf("no finding at the builder's FROM line; got lines %v", keys(byLine))
	}
	shipped, ok := byLine[3]
	if !ok {
		t.Fatalf("no finding at the runtime FROM line; got lines %v", keys(byLine))
	}
	if shipped.Severity == findings.SeverityInfo || shipped.Metadata["image_stage"] != "" {
		t.Errorf("the shipped image's advisory was demoted: severity %s, stage %q", shipped.Severity, shipped.Metadata["image_stage"])
	}
	if built.Severity != findings.SeverityInfo {
		t.Errorf("builder advisory severity %s, want info", built.Severity)
	}
	if built.Metadata["original_severity"] != string(shipped.Severity) ||
		built.Metadata["severity_source"] != "build_stage_only" ||
		built.Metadata["image_stage"] != "builder" {
		t.Errorf("builder metadata: original %q (shipped is %s), source %q, stage %q",
			built.Metadata["original_severity"], shipped.Severity, built.Metadata["severity_source"], built.Metadata["image_stage"])
	}
	if !strings.Contains(built.Message, `build stage "builder"`) || !strings.Contains(built.Message, "--target builder") {
		t.Errorf("message does not say which stage or what --target means: %s", built.Message)
	}
}

func keys(m map[int]findings.Finding) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
