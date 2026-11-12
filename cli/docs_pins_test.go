package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The README told readers to pin the Action at v1.5.0 and the usage guide at
// v0.4.2, sixty releases behind, and MARKETPLACE.md used a movable tag, which
// is the thing nox's own IAC-013 reports. Nothing bumped them because nothing
// knew they existed.
//
// One step already happens after every release: .github/workflows/remediation.yml
// is moved to the new nox. This test ties the documented pin to that line, so
// the same change has to carry the documents with it.

var (
	noxActionUse  = regexp.MustCompile(`uses:\s*nox-hq/nox@(\S+)(.*)`)
	fullCommitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
	pinVersion    = regexp.MustCompile(`^\s*#\s*v(\d+\.\d+\.\d+)\s*$`)
	remediationAt = regexp.MustCompile(`(?m)^\s*nox-version:\s*'(\d+\.\d+\.\d+)'`)
)

// documentedPinFiles are the files a reader copies a workflow from, and the
// composite actions under actions/, which run the scan action at a pinned
// commit: actions/remediate sat on v1.62.0 three releases after
// remediation.yml moved, because nothing compared it.
func documentedPinFiles(t *testing.T) []string {
	t.Helper()
	files := []string{"../README.md", "../MARKETPLACE.md"}
	for _, root := range []string{"../docs", "../examples", "../actions"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			switch filepath.Ext(p) {
			case ".md", ".yml", ".yaml":
				if !d.IsDir() {
					files = append(files, p)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func TestDocumentedActionPinIsTheReleaseNoxRunsItself(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/remediation.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := remediationAt.FindSubmatch(raw)
	if m == nil {
		t.Fatal("remediation.yml no longer carries a nox-version line; this test has nothing to compare against")
	}
	want := string(m[1])

	pins := 0
	shas := map[string]string{} // sha -> first place it was seen
	for _, path := range documentedPinFiles(t) {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(content), "\n") {
			use := noxActionUse.FindStringSubmatch(line)
			if use == nil {
				continue
			}
			pins++
			at := path + ":" + strconv.Itoa(i+1)
			ref, comment := use[1], use[2]
			if !fullCommitSHA.MatchString(ref) {
				t.Errorf("%s pins the Action at %q; a document that tells readers to pin by commit must do it", at, ref)
				continue
			}
			ver := pinVersion.FindStringSubmatch(comment)
			if ver == nil {
				t.Errorf("%s: the pin does not say which release it is (want a trailing `# vX.Y.Z`)", at)
				continue
			}
			if ver[1] != want {
				t.Errorf("%s pins v%s; remediation.yml runs nox %s. Move the documented pins in the change that moves that line (`git rev-parse 'v%s^{commit}'` is the commit)", at, ver[1], want, want)
			}
			if _, seen := shas[ref]; !seen {
				shas[ref] = at
			}
		}
	}
	if pins < 5 {
		t.Fatalf("found %d Action pins in the documents; expected the README, the usage guide and the examples to carry several. The pattern no longer matches and this test checks nothing", pins)
	}
	if len(shas) > 1 {
		t.Errorf("the documents pin %d different commits for one release: %v", len(shas), shas)
	}
}
