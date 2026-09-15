package slop

import "testing"

// SLOP-001 reports an import that resolves to no manifest entry, no standard
// library and no first-party module — the slopsquatting surface, where an LLM
// hallucinates a package name and a developer installs it.
//
// A manifest carries what a project asked for DIRECTLY. The lockfile carries
// the transitive closure. Reading manifests alone therefore made every
// transitive dependency a phantom import, and on the pinned corpus that was the
// largest remaining class: `typing_extensions` 104 findings, `pydantic_core`
// 29, `botocore` 6 — all real, all installed, all present in a lockfile nox was
// not reading. `typing-extensions` appears 25 times in llama_index's uv.lock.
//
// npm was covered through package-lock.json. The Python ecosystem had no
// lockfile reader at all, and pnpm and yarn were missing on the npm side —
// which matters because every repository in the fire-rate corpus uses uv.lock
// or pnpm-lock.yaml, and none of them ships a package-lock.json.

func TestUvLockDeclaresTransitiveDependencies(t *testing.T) {
	const uvLock = `
version = 1
requires-python = ">=3.10"

[[package]]
name = "typing-extensions"
version = "4.12.2"

[[package]]
name = "pydantic-core"
version = "2.23.4"
`
	d := collectDeclared(map[string][]byte{"uv.lock": []byte(uvLock)})
	for _, imp := range []string{"typing_extensions", "pydantic_core"} {
		if !d.hasPyPI(imp) {
			t.Errorf("%s is in uv.lock and still reads as undeclared", imp)
		}
	}
}

func TestPoetryAndPdmLocksUseTheSameShape(t *testing.T) {
	const lock = "[[package]]\nname = \"botocore\"\nversion = \"1.34.0\"\n"
	for _, file := range []string{"poetry.lock", "pdm.lock"} {
		d := collectDeclared(map[string][]byte{file: []byte(lock)})
		if !d.hasPyPI("botocore") {
			t.Errorf("%s: botocore reads as undeclared", file)
		}
	}
}

func TestPipfileLockDeclaresBothSections(t *testing.T) {
	const lock = `{"_meta":{"hash":{}},"default":{"requests":{"version":"==2.31.0"}},
	               "develop":{"pytest":{"version":"==8.0.0"}}}`
	d := collectDeclared(map[string][]byte{"Pipfile.lock": []byte(lock)})
	for _, imp := range []string{"requests", "pytest"} {
		if !d.hasPyPI(imp) {
			t.Errorf("%s is in Pipfile.lock and still reads as undeclared", imp)
		}
	}
}

func TestPnpmLockDeclaresPackages(t *testing.T) {
	const lock = `
packages:

  '@adobe/css-tools@4.4.4':
    resolution: {integrity: sha512-abc==}

  abbrev@2.0.0:
    resolution: {integrity: sha512-def==}

  /legacy-v6-style@1.2.3:
    resolution: {integrity: sha512-ghi==}
`
	d := collectDeclared(map[string][]byte{"pnpm-lock.yaml": []byte(lock)})
	for _, imp := range []string{"@adobe/css-tools", "abbrev", "legacy-v6-style"} {
		if !d.hasNPM(imp) {
			t.Errorf("%s is in pnpm-lock.yaml and still reads as undeclared", imp)
		}
	}
}

func TestYarnLockDeclaresPackages(t *testing.T) {
	const lock = `# yarn lockfile v1

"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.24.0"

lodash@^4.17.21:
  version "4.17.21"
`
	d := collectDeclared(map[string][]byte{"yarn.lock": []byte(lock)})
	for _, imp := range []string{"@babel/core", "lodash"} {
		if !d.hasNPM(imp) {
			t.Errorf("%s is in yarn.lock and still reads as undeclared", imp)
		}
	}
}

// TestAHallucinatedPackageIsStillUndeclared is the recall half: the whole point
// is to report an import that resolves to nothing, and widening what counts as
// declared must not swallow that.
func TestAHallucinatedPackageIsStillUndeclared(t *testing.T) {
	d := collectDeclared(map[string][]byte{
		"uv.lock":        []byte("[[package]]\nname = \"requests\"\n"),
		"pnpm-lock.yaml": []byte("packages:\n\n  abbrev@2.0.0:\n"),
	})
	if d.hasPyPI("requsets_hallucinated") {
		t.Error("a package absent from every lockfile reads as declared")
	}
	if d.hasNPM("@totally/invented") {
		t.Error("an npm package absent from every lockfile reads as declared")
	}
}

// TestEveryLockfileParserIsReachable closes the gap that made every test above
// pass while the analyzer ignored lockfiles entirely.
//
// isManifest decides which files are READ; collectDeclared decides how a file
// that was read is PARSED. Two lists that must agree. The parsers were added to
// the second and not the first, so they were never reached — and the unit tests
// called collectDeclared directly, which is the one path that cannot see the
// difference. The corpus caught it: SLOP-001 stayed at 219 on crewAI with
// `typing-extensions` sitting in its uv.lock.
func TestEveryLockfileParserIsReachable(t *testing.T) {
	for _, base := range []string{
		"poetry.lock", "uv.lock", "pdm.lock", "pipfile.lock",
		"pnpm-lock.yaml", "pnpm-lock.yml", "yarn.lock",
		"package.json", "package-lock.json", "pyproject.toml",
		"pipfile", "setup.py", "setup.cfg", "requirements.txt",
	} {
		if !isManifest(base) {
			t.Errorf("collectDeclared parses %q but isManifest excludes it, so the file "+
				"is never read and the parser never runs", base)
		}
	}
}
