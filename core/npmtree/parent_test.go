package npmtree

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// fakeRegistry answers from a fixed release history and counts the asks.
type fakeRegistry struct {
	rel   map[string]map[string]map[string]string
	asked map[string]int
}

func (f *fakeRegistry) Releases(_ context.Context, pkg string) (map[string]map[string]string, error) {
	if f.asked == nil {
		f.asked = map[string]int{}
	}
	f.asked[pkg]++
	r, ok := f.rel[pkg]
	if !ok {
		return nil, errors.New("no such package: " + pkg)
	}
	return r, nil
}

// The walkthrough app's shape: express 4.21.2 pins body-parser and qs
// exactly, and body-parser 1.20.3 pins qs too, so qs is held twice.
const expressLock = `{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"express": "4.21.2"}},
    "node_modules/express": {"version": "4.21.2", "dependencies": {"body-parser": "1.20.3", "qs": "6.13.0"}},
    "node_modules/body-parser": {"version": "1.20.3", "dependencies": {"qs": "6.13.0"}},
    "node_modules/qs": {"version": "6.13.0"}
  }
}`

// The release history, modelled on express's own: 4.22.1 lets express's
// own copy of qs move but keeps body-parser's range, under which body-parser
// keeps the copy that pins qs 6.13.0.
func expressRegistry() *fakeRegistry {
	return &fakeRegistry{rel: map[string]map[string]map[string]string{
		"express": {
			"4.21.2":      {"body-parser": "1.20.3", "qs": "6.13.0"},
			"4.22.0":      {"body-parser": "~1.20.3", "qs": "~6.14.0"},
			"4.22.1":      {"body-parser": "~1.20.3", "qs": "~6.16.0"},
			"4.22.3":      {"body-parser": "~1.20.5", "qs": "~6.16.0"},
			"5.0.0-beta1": {"body-parser": "^2.0.0", "qs": "^6.16.0"},
			"5.0.0":       {"body-parser": "^2.0.0", "qs": "^6.16.0"},
		},
		"body-parser": {
			"1.20.3": {"qs": "6.13.0"},
			"1.20.5": {"qs": "~6.14.0"},
			"1.20.9": {"qs": "~6.16.1"},
			"2.0.0":  {"qs": "^6.16.0"},
		},
		"qs": {"6.13.0": {}, "6.14.0": {}, "6.14.1": {}, "6.16.0": {}, "6.16.1": {}},
	}}
}

func TestParentReleaseFollowsTheWholeTree(t *testing.T) {
	p := Open(workspace(t, map[string]string{
		"package.json":      `{"dependencies": {"express": "4.21.2"}}`,
		"package-lock.json": expressLock,
	}))

	names, ok := p.ListedAncestors("qs", "6.16.1")
	if !ok || !reflect.DeepEqual(names, []string{"express"}) {
		t.Fatalf("ListedAncestors(qs) = %v, %v; want [express]", names, ok)
	}

	reg := expressRegistry()
	// 4.22.1 allows qs 6.16 for express itself; body-parser's copy stays at
	// 6.13.0 under it. Only the tree as a whole can say 4.22.3.
	up, err := p.ParentRelease(context.Background(), reg, "express", map[string]string{"qs": "6.16.1"})
	if err != nil {
		t.Fatal(err)
	}
	want := ParentUpgrade{Parent: "express", From: "4.21.2", To: "4.22.3", Frees: []string{"qs"}}
	if !reflect.DeepEqual(up, want) {
		t.Fatalf("ParentRelease = %+v, want %+v", up, want)
	}
	if got := up.String(); got != "express 4.21.2 -> 4.22.3" {
		t.Errorf("String() = %q", got)
	}

	for pkg, n := range reg.asked {
		if n != 1 {
			t.Errorf("registry asked %d times about %s within one simulation", n, pkg)
		}
	}

	// Two held packages at once: the one release that frees both.
	up, err = p.ParentRelease(context.Background(), reg, "express", map[string]string{"qs": "6.16.1", "body-parser": "1.20.9"})
	if err != nil || up.To != "4.22.3" || up.FreesList() != "body-parser and qs" {
		t.Fatalf("ParentRelease(both) = %+v, %v", up, err)
	}
}

// A listed package that loads the same held copy but whose range allows the
// fix does not hold it: npm moves the copy under it when express moves. On
// the walkthrough app the plan told the reader to take stripe across a major
// version for qs, and npm, run, left stripe alone and moved qs anyway.
func TestAncestorsAreOnlyThoseThatHold(t *testing.T) {
	p := Open(workspace(t, map[string]string{
		"package.json": `{"dependencies": {"express": "4.21.2", "stripe": "17.5.0"}}`,
		"package-lock.json": `{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"express": "4.21.2", "stripe": "17.5.0"}},
    "node_modules/express": {"version": "4.21.2", "dependencies": {"body-parser": "1.20.3", "qs": "6.13.0"}},
    "node_modules/body-parser": {"version": "1.20.3", "dependencies": {"qs": "6.13.0"}},
    "node_modules/stripe": {"version": "17.5.0", "dependencies": {"qs": "^6.11.0"}},
    "node_modules/qs": {"version": "6.13.0"}
  }
}`,
	}))
	names, ok := p.ListedAncestors("qs", "6.16.1")
	if !ok || !reflect.DeepEqual(names, []string{"express"}) {
		t.Fatalf("ListedAncestors(qs) = %v, %v; want [express]", names, ok)
	}
}

func TestParentReleaseCrossesAMajorOnlyWhenItMust(t *testing.T) {
	p := Open(workspace(t, map[string]string{
		"package.json":      `{"dependencies": {"express": "4.21.2"}}`,
		"package-lock.json": expressLock,
	}))
	reg := expressRegistry()
	// Nothing on 4.x frees body-parser 2.0.0; 5.0.0 does, and the
	// pre-release before it is not a release.
	up, err := p.ParentRelease(context.Background(), reg, "express", map[string]string{"body-parser": "2.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if up.To != "5.0.0" || !up.Major {
		t.Fatalf("ParentRelease = %+v, want 5.0.0 marked major", up)
	}
	// A fix no release reaches is no answer, not an error.
	up, err = p.ParentRelease(context.Background(), reg, "express", map[string]string{"qs": "7.0.0"})
	if err != nil || up.To != "" {
		t.Fatalf("ParentRelease(unreachable) = %+v, %v; want zero", up, err)
	}
}

func TestParentReleaseRefusesWhatItCannotRead(t *testing.T) {
	p := Open(workspace(t, map[string]string{
		"package.json":      `{"dependencies": {"express": "4.21.2"}}`,
		"package-lock.json": expressLock,
	}))
	// A registry that fails is an error, never "no release frees it".
	if _, err := p.ParentRelease(context.Background(), &fakeRegistry{}, "express", map[string]string{"qs": "6.16.1"}); err == nil {
		t.Error("a failed registry lookup was not reported")
	}
	if _, ok := p.ListedAncestors("express", "5.0.0"); ok {
		t.Error("a package the project lists has no ancestor to upgrade")
	}
	pn := Open(workspace(t, map[string]string{"package.json": `{}`, "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"}))
	if _, ok := pn.ListedAncestors("qs", "6.16.1"); ok {
		t.Error("pnpm's lockfile records no ranges; no ancestor can be established")
	}
}
