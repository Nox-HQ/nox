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

// nox-hq.dev's shape, reduced: vite pins nanoid 5.x for itself and depends on
// postcss, which keeps its own nanoid on the 3.x line. The 5.x finding's fix is
// 5.1.16. The 3.x copy can never reach it, and it is not the finding's copy.
const twoLineLock = `{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"vite": "6.4.1"}},
    "node_modules/vite": {"version": "6.4.1", "dependencies": {"nanoid": "5.1.6", "postcss": "8.5.6"}},
    "node_modules/nanoid": {"version": "5.1.6"},
    "node_modules/postcss": {"version": "8.5.6", "dependencies": {"nanoid": "^3.3.11"}},
    "node_modules/postcss/node_modules/nanoid": {"version": "3.3.11"}
  }
}`

func twoLineRegistry() *fakeRegistry {
	return &fakeRegistry{rel: map[string]map[string]map[string]string{
		"vite": {
			"6.4.1": {"nanoid": "5.1.6", "postcss": "8.5.6"},
			"6.4.5": {"nanoid": "^5.1.16", "postcss": "8.5.6"},
		},
		"postcss": {"8.5.6": {"nanoid": "^3.3.11"}},
		"nanoid":  {"3.3.11": {}, "5.1.6": {}, "5.1.16": {}},
	}}
}

func TestAParentReleaseIsJudgedOnTheFindingsLine(t *testing.T) {
	p := Open(workspace(t, map[string]string{
		"package.json":      `{"dependencies": {"vite": "6.4.1"}}`,
		"package-lock.json": twoLineLock,
	}))
	up, err := p.ParentReleaseFrom(context.Background(), twoLineRegistry(), "vite",
		map[string]string{"nanoid": "5.1.16"}, map[string]string{"nanoid": "5.1.6"})
	if err != nil {
		t.Fatal(err)
	}
	if up.To != "6.4.5" {
		t.Fatalf("ParentReleaseFrom = %+v; want vite 6.4.5, which moves the 5.x copy and leaves postcss's 3.x copy alone", up)
	}
	// With no line given, every copy is judged, as before: the 3.x copy holds.
	if old, _ := p.ParentRelease(context.Background(), twoLineRegistry(), "vite", map[string]string{"nanoid": "5.1.16"}); old.To != "" {
		t.Errorf("ParentRelease without a line = %+v; want none, the documented all-copies answer", old)
	}
}

func TestAncestorsAreOnlyThoseOfTheFindingsLine(t *testing.T) {
	p := Open(workspace(t, map[string]string{
		"package.json": `{"dependencies": {"app-lib": "1.0.0", "postcss": "8.5.6"}}`,
		"package-lock.json": `{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"app-lib": "1.0.0", "postcss": "8.5.6"}},
    "node_modules/app-lib": {"version": "1.0.0", "dependencies": {"nanoid": "5.1.6"}},
    "node_modules/nanoid": {"version": "5.1.6"},
    "node_modules/postcss": {"version": "8.5.6", "dependencies": {"nanoid": "^3.3.11"}},
    "node_modules/postcss/node_modules/nanoid": {"version": "3.3.11"}
  }
}`,
	}))
	names, ok := p.ListedAncestorsFrom("nanoid", "5.1.6", "5.1.16")
	if !ok || !reflect.DeepEqual(names, []string{"app-lib"}) {
		t.Errorf("ListedAncestorsFrom(nanoid 5.1.6) = %v, %v; want [app-lib]: postcss holds only the 3.x copy", names, ok)
	}
}
