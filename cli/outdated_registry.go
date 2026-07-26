package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Multi-ecosystem support for `nox fix --outdated`.
//
// Currency needs two things that vulnerability scanning does not, which is why
// it cannot simply reuse the deps analyzer:
//
//  1. WHICH DEPENDENCIES ARE DIRECT. deps.Package is parsed from lockfiles,
//     which are flat and contain the entire transitive closure. Upgrading a
//     transitive package writes an explicit requirement for something the
//     project never imports — churn the operator then has to unpick. Directness
//     is declared in the MANIFEST (package.json, Cargo.toml, requirements.txt),
//     so both files are read: names from the manifest, resolved versions from
//     the lockfile.
//
//  2. WHAT THE LATEST VERSION IS, which only a registry can answer. Go gets
//     this from `go list -m -u`; every other ecosystem needs an HTTP call.
//
// Registries are queried directly rather than shelling out to npm/pip/cargo,
// so planning needs no toolchain and behaves the same everywhere. Applying an
// upgrade still uses the native command, which is where a toolchain genuinely
// belongs.

// directDep is one direct dependency with its currently-resolved version.
// An empty version means the manifest pins a range and no lockfile entry
// resolved it; the planner skips those rather than inventing a current version.
type directDep struct {
	eco     string
	name    string
	version string
}

// registryBase maps an ecosystem to its default registry root. Overridable per
// call so tests can point at a stub.
var registryBase = map[string]string{
	"npm":   "https://registry.npmjs.org",
	"pypi":  "https://pypi.org",
	"cargo": "https://crates.io",
}

var httpClient = &http.Client{Timeout: 20 * time.Second}

// resolveLatest asks an ecosystem's registry for the latest STABLE version.
//
// Each registry expresses that differently, and picking the wrong field means
// silently proposing a prerelease: npm publishes channels under dist-tags where
// only `latest` is stable, and crates.io reports both max_version (which
// includes prereleases) and max_stable_version.
func resolveLatest(eco, pkg, base string) (string, error) {
	if base == "" {
		base = registryBase[eco]
	}
	if base == "" {
		return "", fmt.Errorf("no registry configured for ecosystem %q", eco)
	}

	var url string
	switch eco {
	case "npm":
		url = base + "/" + pkg
	case "pypi":
		url = base + "/pypi/" + pkg + "/json"
	case "cargo":
		url = base + "/api/v1/crates/" + pkg
	default:
		return "", fmt.Errorf("ecosystem %q has no currency resolver yet", eco)
	}

	req, err := http.NewRequest(http.MethodGet, url, http.NoBody) //nolint:noctx // short-lived CLI call with a client timeout
	if err != nil {
		return "", fmt.Errorf("%s registry: %w", eco, err)
	}
	if eco == "npm" {
		// The full packument for a popular package is enormous — typescript and
		// @types/node both exceed 8 MB, which silently truncated the read and
		// surfaced as "unexpected end of JSON input". The abbreviated document
		// carries dist-tags and is orders of magnitude smaller.
		req.Header.Set("Accept", "application/vnd.npm.install-v1+json")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s registry: %w", eco, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Anything but 200 is an error, never an empty result. A silent "" would be
	// indistinguishable from "already current", so a rate-limited or unreachable
	// registry would quietly report the whole project as up to date.
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s registry returned HTTP %d for %s", eco, resp.StatusCode, pkg)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return "", fmt.Errorf("reading %s registry response: %w", eco, err)
	}

	switch eco {
	case "npm":
		var doc struct {
			DistTags map[string]string `json:"dist-tags"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return "", fmt.Errorf("parsing npm response for %s: %w", pkg, err)
		}
		return doc.DistTags["latest"], nil
	case "pypi":
		var doc struct {
			Info struct {
				Version string `json:"version"`
			} `json:"info"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return "", fmt.Errorf("parsing pypi response for %s: %w", pkg, err)
		}
		return doc.Info.Version, nil
	case "cargo":
		var doc struct {
			Crate struct {
				MaxStable string `json:"max_stable_version"`
				Max       string `json:"max_version"`
			} `json:"crate"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return "", fmt.Errorf("parsing crates.io response for %s: %w", pkg, err)
		}
		// max_version includes prereleases; max_stable_version is the one a
		// currency pass wants. Fall back only when no stable release exists.
		if doc.Crate.MaxStable != "" {
			return doc.Crate.MaxStable, nil
		}
		return doc.Crate.Max, nil
	}
	return "", fmt.Errorf("unreachable resolver for %q", eco)
}

// pkgNameForPath recovers the package name from a stub registry path. Test
// helper kept beside the resolver so the two stay in step.
func pkgNameForPath(path, eco string) string {
	switch eco {
	case "npm":
		return strings.TrimPrefix(path, "/")
	case "pypi":
		return strings.TrimSuffix(strings.TrimPrefix(path, "/pypi/"), "/json")
	case "cargo":
		return strings.TrimPrefix(path, "/api/v1/crates/")
	}
	return path
}

// directDeps enumerates direct dependencies across every ecosystem whose
// manifest is present in root. Missing or malformed manifests are skipped
// rather than failing: a repo with a broken package.json should still get its
// Cargo dependencies checked.
func directDeps(root string) []directDep {
	var out []directDep
	out = append(out, npmDirectDeps(root)...)
	out = append(out, cargoDirectDeps(root)...)
	out = append(out, pypiDirectDeps(root)...)
	return out
}

func readIfPresent(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

// npmDirectDeps reads names from package.json (dependencies AND
// devDependencies — a dev dependency still runs in CI and still carries
// vulnerabilities) and resolved versions from package-lock.json.
func npmDirectDeps(root string) []directDep {
	raw := readIfPresent(filepath.Join(root, "package.json"))
	if raw == nil {
		return nil
	}
	var manifest struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil
	}

	resolved := map[string]string{}
	if lock := readIfPresent(filepath.Join(root, "package-lock.json")); lock != nil {
		var doc struct {
			Packages map[string]struct {
				Version string `json:"version"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(lock, &doc); err == nil {
			for path, e := range doc.Packages {
				// Keys look like "node_modules/express" or
				// "node_modules/@scope/thing"; the root package has key "".
				if name, ok := strings.CutPrefix(path, "node_modules/"); ok {
					resolved[name] = e.Version
				}
			}
		}
	}

	var out []directDep
	for _, set := range []map[string]string{manifest.Dependencies, manifest.DevDependencies} {
		for name := range set {
			out = append(out, directDep{eco: "npm", name: name, version: resolved[name]})
		}
	}
	return out
}

var cargoDepLine = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*=`)

// cargoDirectDeps reads the [dependencies] and [dev-dependencies] tables of
// Cargo.toml for names, and Cargo.lock for resolved versions. Only the key is
// taken from the manifest, so both `serde = "1"` and the table form
// `tokio = { version = "1.20" }` are handled.
func cargoDirectDeps(root string) []directDep {
	raw := readIfPresent(filepath.Join(root, "Cargo.toml"))
	if raw == nil {
		return nil
	}

	names := map[string]bool{}
	inDeps := false
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			inDeps = t == "[dependencies]" || t == "[dev-dependencies]" || t == "[build-dependencies]"
			continue
		}
		if !inDeps || t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if m := cargoDepLine.FindStringSubmatch(line); m != nil {
			names[m[1]] = true
		}
	}

	resolved := map[string]string{}
	if lock := readIfPresent(filepath.Join(root, "Cargo.lock")); lock != nil {
		var name string
		for _, line := range strings.Split(string(lock), "\n") {
			t := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(t, "name = "):
				name = strings.Trim(strings.TrimPrefix(t, "name = "), `"`)
			case strings.HasPrefix(t, "version = ") && name != "":
				resolved[name] = strings.Trim(strings.TrimPrefix(t, "version = "), `"`)
				name = ""
			}
		}
	}

	var out []directDep
	for name := range names {
		out = append(out, directDep{eco: "cargo", name: name, version: resolved[name]})
	}
	return out
}

// pypiExactPin matches only `name == version`. A range (`>=2.0,<3.0`) has no
// single current version, so it is recorded with an empty version and skipped
// by the planner rather than being assigned a version it does not have.
var pypiExactPin = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)`)
var pypiAnyReq = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~]|$)`)

func pypiDirectDeps(root string) []directDep {
	raw := readIfPresent(filepath.Join(root, "requirements.txt"))
	if raw == nil {
		return nil
	}
	var out []directDep
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		// Strip inline comments before matching, so `urllib3 == 1.26.12  # x`
		// does not carry the comment into the version.
		if i := strings.Index(t, "#"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		// Skip blanks, editable installs, options and requirement includes.
		if t == "" || strings.HasPrefix(t, "-") {
			continue
		}
		if m := pypiExactPin.FindStringSubmatch(t); m != nil {
			out = append(out, directDep{eco: "pypi", name: m[1], version: m[2]})
			continue
		}
		if m := pypiAnyReq.FindStringSubmatch(t); m != nil {
			out = append(out, directDep{eco: "pypi", name: m[1]})
		}
	}
	return out
}

// planRegistryCurrency plans upgrades for every non-Go ecosystem found in root.
//
// Failures are reported, never swallowed: a registry that is unreachable or
// rate-limiting must not make a project look up to date. Each is returned as a
// degradation string so the caller can print them, matching nox's "report what
// you could not check" model.
func planRegistryCurrency(root string, includeMajor bool, base map[string]string) (plan upgradePlan, degraded []string) {
	for _, d := range directDeps(root) {
		if d.version == "" {
			// A range pin with no lockfile entry: there is no single current
			// version to compare, so there is nothing honest to say.
			plan.skipped++
			continue
		}
		latest, err := resolveLatest(d.eco, d.name, base[d.eco])
		if err != nil {
			degraded = append(degraded, fmt.Sprintf("%s/%s: %v", d.eco, d.name, err))
			continue
		}
		if latest == "" || !versionLess(d.version, latest) {
			continue
		}
		if !includeMajor && isMajorBump(d.version, latest) {
			plan.majorSkipped++
			continue
		}
		plan.actions = append(plan.actions, upgradeAction{
			ruleID:    "OUTDATED",
			pkg:       d.name,
			fromVer:   d.version,
			toVersion: latest,
			ecosystem: d.eco,
			action:    supportedFixEcosystems[d.eco],
		})
	}
	return plan, degraded
}
