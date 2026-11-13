package deps

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/vulnsource"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/image"
)

// fakeImages answers for named digests and records what it was asked.
type fakeImages struct {
	contents map[string]image.Contents // by name@digest
	err      error
	asked    []string
}

func (f *fakeImages) Contents(_ context.Context, name, digest string) (image.Contents, error) {
	f.asked = append(f.asked, name+"@"+digest)
	if f.err != nil {
		return image.Contents{}, f.err
	}
	c, ok := f.contents[name+"@"+digest]
	if !ok {
		return image.Contents{}, errors.New("not found")
	}
	return c, nil
}

const goImageDigest = "sha256:df23b876380eb556f22bbba2fa57493e8684fc4fcabf06399fbfb65359978d28"

func dockerfileTree(t *testing.T, from string) []discovery.Artifact {
	t.Helper()
	dir := t.TempDir()
	mod := filepath.Join(dir, "go.mod")
	_ = os.WriteFile(mod, []byte("module example.com/tree\n\ngo 1.21\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644)
	df := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(df, []byte("# build\nFROM "+from+" AS build\nRUN go build ./...\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return []discovery.Artifact{
		{Path: "go.mod", AbsPath: mod, Type: discovery.Lockfile},
		{Path: "Dockerfile", AbsPath: df, Type: discovery.Container},
	}
}

// A digest-pinned base image's installed software is inventoried at its FROM
// line, and an advisory against it is judged as what it is: software inside
// the image. The source tree beside the Dockerfile does not decide it, any
// more than it decides a compiled binary's (the wrong-input hazard).
func TestPinnedImageIsInventoriedAndNotJudgedByTheTree(t *testing.T) {
	imgs := &fakeImages{contents: map[string]image.Contents{
		"golang:1.26-alpine@" + goImageDigest: {Distro: "alpine:v3.24", Packages: []image.Package{
			{Name: "stdlib", Version: "1.26.0", Ecosystem: "go", Path: "usr/local/go/VERSION"},
			{Name: "openssl", Version: "3.5.1-r0", Ecosystem: "alpine:v3.24", Path: "lib/apk/db/installed"},
		}},
	}}
	rec := vulnsource.Record{
		ID: "GO-2099-0002", Summary: "smuggling",
		Severity: []vulnsource.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		// A fixed release exists, so the severity reflects only whether the
		// tree was (wrongly) allowed to judge the image.
		Affected: []vulnsource.Affected{{
			Package:           vulnsource.Package{Name: "stdlib", Ecosystem: "Go"},
			Ranges:            []vulnsource.Range{{Type: "SEMVER", Events: []vulnsource.Event{{Introduced: "0"}, {Fixed: "1.26.1"}}}},
			EcosystemSpecific: vulnsource.EcosystemSpecific{Imports: []vulnsource.Import{{Path: "net/http"}}},
		}},
	}
	src := &stubSource{name: "stub", records: map[string][]vulnsource.Record{"stdlib": {rec}}}
	inv, fs, err := NewAnalyzer(WithSource(src), WithImages(imgs)).ScanArtifacts(context.Background(),
		dockerfileTree(t, "golang:1.26-alpine@"+goImageDigest))
	if err != nil {
		t.Fatal(err)
	}
	var have []string
	for _, p := range inv.Packages() {
		switch {
		case p.Ecosystem == "docker" && p.Origin != OriginImage:
			t.Errorf("the image reference was read but not marked: %+v", p)
		case p.Ecosystem == "docker":
		case p.Origin == OriginImage:
			have = append(have, p.Ecosystem+" "+p.Name+" "+p.Version)
		}
	}
	if strings.Join(have, "|") != "go stdlib 1.26.0|alpine:v3.24 openssl 3.5.1-r0" &&
		strings.Join(have, "|") != "alpine:v3.24 openssl 3.5.1-r0|go stdlib 1.26.0" {
		t.Errorf("image packages %v", have)
	}
	var got *findings.Finding
	for _, f := range fs.Findings() {
		if f.RuleID == "VULN-001" && f.Metadata["package"] == "stdlib" {
			got = &f
		}
	}
	if got == nil {
		t.Fatal("no finding for the image's stdlib")
	}
	if got.Location.FilePath != "Dockerfile" || got.Metadata["package_origin"] != OriginImage ||
		got.Metadata["image"] != "golang:1.26-alpine@"+goImageDigest {
		t.Errorf("located %q, origin %q, image %q", got.Location.FilePath, got.Metadata["package_origin"], got.Metadata["image"])
	}
	if got.Metadata["applicability"] != "undetermined" || got.Severity == findings.SeverityInfo {
		t.Errorf("applicability %q severity %s: the tree decided an image's advisory", got.Metadata["applicability"], got.Severity)
	}
}

// A tag names no fixed content, so it is not resolved: the scan says the image
// was not checked and why, and nothing is fetched.
func TestTaggedImageIsNotCheckedAndSaysWhy(t *testing.T) {
	imgs := &fakeImages{}
	d := &degrade.Degradations{}
	a := NewAnalyzer(WithOSVDisabled(), WithImages(imgs), WithDegradations(d))
	if _, _, err := a.ScanArtifacts(context.Background(), dockerfileTree(t, "golang:1.26-alpine")); err != nil {
		t.Fatal(err)
	}
	if len(imgs.asked) != 0 {
		t.Errorf("a tagged image was fetched: %v", imgs.asked)
	}
	if !degradationMentions(d, "golang:1.26-alpine", "digest") {
		t.Errorf("no degradation saying the tagged image was not checked: %+v", d.Items())
	}
}

// An image that cannot be read is named, with the reason.
func TestUnreadableImageIsNamed(t *testing.T) {
	imgs := &fakeImages{err: errors.New("registry-1.docker.io: the registry refused an anonymous pull")}
	d := &degrade.Degradations{}
	a := NewAnalyzer(WithOSVDisabled(), WithImages(imgs), WithDegradations(d))
	if _, _, err := a.ScanArtifacts(context.Background(), dockerfileTree(t, "golang:1.26-alpine@"+goImageDigest)); err != nil {
		t.Fatal(err)
	}
	if !degradationMentions(d, "golang:1.26-alpine@"+goImageDigest, "anonymous pull") {
		t.Errorf("no degradation naming the unreadable image: %+v", d.Items())
	}
}

// Without image checking on, nothing is fetched: it is opt-in until measured.
func TestImagesAreNotReadUnlessOn(t *testing.T) {
	inv, _, err := NewAnalyzer(WithOSVDisabled()).ScanArtifacts(context.Background(), dockerfileTree(t, "golang:1.26-alpine@"+goImageDigest))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range inv.Packages() {
		if p.Origin == OriginImage {
			t.Errorf("an image package without image checking: %+v", p)
		}
	}
}

func degradationMentions(deg *degrade.Degradations, parts ...string) bool {
	for _, d := range deg.Items() {
		text := d.Detail + " " + d.Impact
		all := true
		for _, p := range parts {
			if !strings.Contains(text, p) {
				all = false
			}
		}
		if all {
			return true
		}
	}
	return false
}

// Debian rates each advisory for its release. An entry it calls unimportant
// is recorded, not dropped, and out of gating severity whatever its CVSS says;
// other ratings travel with the finding and leave the severity alone.
func TestDebianUrgencyTravelsAndUnimportantDoesNotGate(t *testing.T) {
	const digest = "sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d"
	imgs := &fakeImages{contents: map[string]image.Contents{
		"node:22-bookworm-slim@" + digest: {Distro: "debian:12", Packages: []image.Package{
			{Name: "coreutils", Version: "9.1-1", Ecosystem: "debian:12"},
			{Name: "glibc", Version: "2.36-9+deb12u14", Ecosystem: "debian:12"},
		}},
	}}
	high := []vulnsource.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
	rec := func(id, pkg, urgency string) vulnsource.Record {
		return vulnsource.Record{ID: id, Summary: id, Severity: high, Affected: []vulnsource.Affected{{
			Package: vulnsource.Package{Name: pkg, Ecosystem: "Debian:12"},
			// Fixed releases exist, so only Debian's rating moves the severity.
			Ranges:            []vulnsource.Range{{Type: "ECOSYSTEM", Events: []vulnsource.Event{{Introduced: "0"}, {Fixed: "99.0-1"}}}},
			EcosystemSpecific: vulnsource.EcosystemSpecific{Urgency: urgency},
		}}}
	}
	src := &stubSource{name: "stub", records: map[string][]vulnsource.Record{
		"coreutils": {rec("DEBIAN-CVE-2025-5278", "coreutils", "unimportant")},
		"glibc":     {rec("DEBIAN-CVE-2026-5435", "glibc", "low")},
	}}
	_, fs, err := NewAnalyzer(WithSource(src), WithImages(imgs)).ScanArtifacts(context.Background(),
		dockerfileTree(t, "node:22-bookworm-slim@"+digest))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]findings.Finding{}
	for _, f := range fs.Findings() {
		if f.RuleID == "VULN-001" {
			got[f.Metadata["package"]] = f
		}
	}
	cu, ok := got["coreutils"]
	if !ok {
		t.Fatal("the unimportant advisory was dropped; it must be recorded")
	}
	if cu.Severity != findings.SeverityInfo || cu.Metadata["distro_urgency"] != "unimportant" ||
		!strings.Contains(cu.Message, "unimportant") {
		t.Errorf("unimportant: severity %s, urgency %q, message %q", cu.Severity, cu.Metadata["distro_urgency"], cu.Message)
	}
	gl := got["glibc"]
	if gl.Severity == findings.SeverityInfo || gl.Metadata["distro_urgency"] != "low" {
		t.Errorf("low: severity %s, urgency %q; the rating should travel and the severity stay", gl.Severity, gl.Metadata["distro_urgency"])
	}
}

// Ubuntu rates with a severity entry; "negligible" is its "unimportant".
func TestUbuntuNegligibleDoesNotGate(t *testing.T) {
	const digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	imgs := &fakeImages{contents: map[string]image.Contents{
		"ubuntu:24.04@" + digest: {Distro: "ubuntu:24.04:LTS", Packages: []image.Package{
			{Name: "openssl", Version: "3.0.13-0ubuntu3.1", Ecosystem: "ubuntu:24.04:LTS"},
		}},
	}}
	src := &stubSource{name: "stub", records: map[string][]vulnsource.Record{"openssl": {{
		ID: "UBUNTU-CVE-2099-1", Summary: "x",
		Severity: []vulnsource.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, {Type: "Ubuntu", Score: "negligible"}},
		Affected: []vulnsource.Affected{{
			Package: vulnsource.Package{Name: "openssl", Ecosystem: "Ubuntu:24.04:LTS"},
			Ranges:  []vulnsource.Range{{Type: "ECOSYSTEM", Events: []vulnsource.Event{{Introduced: "0"}, {Fixed: "3.0.13-0ubuntu3.2"}}}},
		}},
	}}}}
	_, fs, err := NewAnalyzer(WithSource(src), WithImages(imgs)).ScanArtifacts(context.Background(), dockerfileTree(t, "ubuntu:24.04@"+digest))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs.Findings() {
		if f.RuleID == "VULN-001" && f.Metadata["package"] == "openssl" {
			if f.Severity != findings.SeverityInfo || f.Metadata["distro_urgency"] != "negligible" || f.Metadata["fixed_in"] != "3.0.13-0ubuntu3.2" {
				t.Errorf("severity %s urgency %q fixed_in %q", f.Severity, f.Metadata["distro_urgency"], f.Metadata["fixed_in"])
			}
			return
		}
	}
	t.Fatal("no finding for the image's openssl")
}

// Only an advisory with a fix gates. One the image's own release has not
// fixed is recorded at info with its real severity kept: failing a build on
// what nobody can install yet teaches people to turn the check off. A
// package from the tree, with or without a fix, is untouched.
func TestUnfixedImageAdvisoryDoesNotGate(t *testing.T) {
	const digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	imgs := &fakeImages{contents: map[string]image.Contents{
		"debian:12@" + digest: {Distro: "debian:12", Packages: []image.Package{
			{Name: "glibc", Version: "2.36-9+deb12u14", Ecosystem: "debian:12"},
			{Name: "openssl", Version: "3.0.15-1~deb12u1", Ecosystem: "debian:12"},
		}},
	}}
	high := []vulnsource.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
	deb := func(id, pkg string, events ...vulnsource.Event) vulnsource.Record {
		return vulnsource.Record{ID: id, Summary: id, Severity: high, Affected: []vulnsource.Affected{{
			Package: vulnsource.Package{Name: pkg, Ecosystem: "Debian:12"},
			Ranges:  []vulnsource.Range{{Type: "ECOSYSTEM", Events: events}},
		}}}
	}
	src := &stubSource{name: "stub", records: map[string][]vulnsource.Record{
		"glibc":   {deb("DEBIAN-CVE-2099-1", "glibc", vulnsource.Event{Introduced: "0"})},
		"openssl": {deb("DEBIAN-CVE-2099-2", "openssl", vulnsource.Event{Introduced: "0"}, vulnsource.Event{Fixed: "3.0.15-1~deb12u2"})},
	}}
	_, fs, err := NewAnalyzer(WithSource(src), WithImages(imgs)).ScanArtifacts(context.Background(), dockerfileTree(t, "debian:12@"+digest))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]findings.Finding{}
	for _, f := range fs.Findings() {
		if f.RuleID == "VULN-001" {
			got[f.Metadata["package"]] = f
		}
	}
	unfixed, fixed := got["glibc"], got["openssl"]
	if unfixed.Severity != findings.SeverityInfo || unfixed.Metadata["original_severity"] != string(findings.SeverityCritical) ||
		!strings.Contains(unfixed.Message, "no fix") {
		t.Errorf("unfixed: severity %s, original %q, message %q", unfixed.Severity, unfixed.Metadata["original_severity"], unfixed.Message)
	}
	if fixed.Severity != findings.SeverityCritical || fixed.Metadata["fixed_in"] != "3.0.15-1~deb12u2" {
		t.Errorf("fixed: severity %s fixed_in %q; a fixable advisory must gate", fixed.Severity, fixed.Metadata["fixed_in"])
	}
}
