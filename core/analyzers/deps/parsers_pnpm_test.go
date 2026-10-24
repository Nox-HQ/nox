package deps

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The fixtures below are verbatim excerpts of real lockfiles, one per pnpm
// lockfile layout; testdata/lockfiles/SOURCES.md names each source and the
// entries cut from it. Each expected list was computed from the fixture by
// PyYAML, not by this parser.
//
// Every one of them carries the shape that produced phantom packages: a
// `peerDependenciesMeta:` block whose children are scoped package NAMES used as
// keys ('@angular/compiler':, '@modelcontextprotocol/sdk':). Those are fields of
// a package, not packages, and on vercel/ai they became "@angular" at version
// "compiler" — in the inventory, both SBOMs, OSV lookups and the typosquat check.

// pnpmFixture parses one vendored pnpm fixture and returns "name@version"
// strings, sorted, so an expectation is an exact set rather than a subset.
func pnpmFixture(t *testing.T, dir string) []string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", "lockfiles", dir, "pnpm-lock.yaml"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	pkgs, err := parsePnpmLock(data)
	if err != nil {
		t.Fatalf("parsePnpmLock: %v", err)
	}

	got := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Ecosystem != "npm" {
			t.Errorf("%s: ecosystem %q, want npm", p.Name, p.Ecosystem)
		}
		got = append(got, p.Name+"@"+p.Version)
	}
	sort.Strings(got)
	return got
}

func assertExactPackages(t *testing.T, got, want []string) {
	t.Helper()

	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("packages differ\n got: %q\nwant: %q", got, want)
	}
}

// TestParsePnpmLock_V5_4 covers lockfileVersion 5.4 (pnpm 7): "/name/version"
// keys, peer suffixes after '_' — both the readable "_jsdom@21.1.0+terser@5.15.1"
// and the hashed "_td6yqss6ra3qoebludh4ctrhym" — and package names that contain
// '_' themselves (evp_bytestokey, string_decoder).
//
// The two vite@4.0.4 entries differ only in their peer suffix: one package.
func TestParsePnpmLock_V5_4(t *testing.T) {
	t.Parallel()

	assertExactPackages(t, pnpmFixture(t, "pnpm-v5.4"), []string{
		"@babel/core@7.16.0",
		"@babel/helper-compilation-targets@7.16.3",
		"eslint-plugin-jest@27.2.1",
		"evp_bytestokey@1.0.3",
		"string_decoder@1.1.1",
		"vite@4.0.4",
		"vitest@0.28.2",
	})
}

// TestParsePnpmLock_V6_Peers covers lockfileVersion 6.0: "/name@version" keys
// with one or more "(peer@version)" suffixes, scoped peers inside them, and
// peerDependenciesMeta blocks keyed by scoped names.
func TestParsePnpmLock_V6_Peers(t *testing.T) {
	t.Parallel()

	assertExactPackages(t, pnpmFixture(t, "pnpm-v6-peers"), []string{
		"@aashutoshrathi/word-wrap@1.2.6",
		"@babel/core@7.23.5",
		"@babel/helper-module-transforms@7.23.3",
		"eslint-module-utils@2.8.0",
		"string_decoder@1.1.1",
		"vite@5.1.4",
		"vitest@1.3.1",
	})
}

// TestParsePnpmLock_V9_PackagesOnly covers lockfileVersion 9.0: packages come
// from `packages:` (dependency IDs, no slash) and nowhere else. `snapshots:`
// repeats every package with peer suffixes, and `importers:` lists each
// workspace member's direct dependencies under scoped-name keys; reading either
// would duplicate or invent packages.
func TestParsePnpmLock_V9_PackagesOnly(t *testing.T) {
	t.Parallel()

	assertExactPackages(t, pnpmFixture(t, "pnpm-v9"), []string{
		"@adobe/css-tools@4.4.4",
		"@angular/core@20.3.25",
		"@google/genai@1.52.0",
		"@types/babel__core@7.20.5",
		"string_decoder@1.1.1",
	})
}

// TestParsePnpmLock_V9_MultiDocument covers the two-document lockfile pnpm
// writes when it manages its own version: a first YAML document locking pnpm
// itself, then `---` and the project's lockfile. A decoder that reads one
// document sees only pnpm's binaries and loses the project.
func TestParsePnpmLock_V9_MultiDocument(t *testing.T) {
	t.Parallel()

	got := pnpmFixture(t, "pnpm-v9-multidoc")
	for _, want := range []string{"@auth/core@0.41.3", "@lerna-lite/core@5.6.3", "pnpm@12.4.1"} {
		if !containsString(got, want) {
			t.Errorf("%s missing from %q", want, got)
		}
	}
	if len(got) != 17 {
		t.Errorf("got %d packages, want 17 (15 in the pnpm document, 2 in the project): %q", len(got), got)
	}
}

// TestParsePnpmLock_V9_GitAndTarball covers dependencies keyed by URL rather
// than version. The spec writes a `version:` field exactly when the key does
// not carry one; reading the key alone yields the URL as the version, which no
// advisory matches.
func TestParsePnpmLock_V9_GitAndTarball(t *testing.T) {
	t.Parallel()

	assertExactPackages(t, pnpmFixture(t, "pnpm-v9-git-tarball"), []string{
		"@erc6900/reference-implementation@0.8.0",
		"accountabstraction@0.9.0",
		"solady@0.0.237",
		"solhint@3.6.2",
	})
}

// TestParsePnpmLock_WithoutLockfileVersion removes the lockfileVersion line
// from each real fixture: the key layout must then be recognised from the keys
// themselves, with the same result.
func TestParsePnpmLock_WithoutLockfileVersion(t *testing.T) {
	t.Parallel()

	for _, dir := range []string{"pnpm-v5.4", "pnpm-v6-peers", "pnpm-v9", "pnpm-v9-git-tarball"} {
		t.Run(dir, func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(filepath.Join("testdata", "lockfiles", dir, "pnpm-lock.yaml"))
			if err != nil {
				t.Fatalf("reading fixture: %v", err)
			}
			_, rest, found := strings.Cut(string(data), "\n")
			if !found || !strings.HasPrefix(string(data), "lockfileVersion:") {
				t.Fatal("fixture does not start with lockfileVersion")
			}
			pkgs, err := parsePnpmLock([]byte(rest))
			if err != nil {
				t.Fatalf("parsePnpmLock: %v", err)
			}
			got := make([]string, 0, len(pkgs))
			for _, p := range pkgs {
				got = append(got, p.Name+"@"+p.Version)
			}
			sort.Strings(got)
			assertExactPackages(t, got, pnpmFixture(t, dir))
		})
	}
}

// TestParsePnpmLock_NoPhantomPackages runs every vendored pnpm fixture and
// rejects the defect's signature directly: a name that is only a scope
// ("@angular") or a version that is not a version ("compiler").
func TestParsePnpmLock_NoPhantomPackages(t *testing.T) {
	t.Parallel()

	for _, dir := range []string{"pnpm-v5.4", "pnpm-v6", "pnpm-v6-peers", "pnpm-v9", "pnpm-v9-multidoc", "pnpm-v9-git-tarball"} {
		t.Run(dir, func(t *testing.T) {
			t.Parallel()

			for _, p := range pnpmFixture(t, dir) {
				name, version := splitAtVersion(p)
				if strings.HasPrefix(name, "@") && !strings.Contains(name, "/") {
					t.Errorf("%s: name is a bare scope", p)
				}
				if version == "" || version[0] < '0' || version[0] > '9' {
					t.Errorf("%s: version is not a version", p)
				}
			}
		})
	}
}

// TestParsePnpmLock_MalformedYAMLIsAnError pins that a lockfile which is not
// valid YAML fails loudly. The caller records the error as a degradation
// naming the file, so the operator learns those dependencies were not scanned.
func TestParsePnpmLock_MalformedYAMLIsAnError(t *testing.T) {
	t.Parallel()

	truncated := "lockfileVersion: '9.0'\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-abc\n"
	if _, err := parsePnpmLock([]byte(truncated)); err == nil {
		t.Fatal("a truncated lockfile parsed without error")
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// splitAtVersion splits "name@version", where a leading '@' marks a scope.
func splitAtVersion(s string) (name, version string) {
	if idx := strings.LastIndex(s, "@"); idx > 0 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}
