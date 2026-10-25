package mcpconfig

import (
	"regexp"
	"strings"
)

// Ecosystems a package-runner launch names, in OSV's vocabulary.
const (
	EcosystemNPM  = "npm"
	EcosystemPyPI = "PyPI"
)

var (
	// exactVersionRe is a concrete release: 1.2.3, 2025.1.14, 1.0.0-rc.1.
	exactVersionRe = regexp.MustCompile(`^v?\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?$`)
	pipNameRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*`)
	pipSepRe       = regexp.MustCompile(`[-_.]+`)
)

// runnerEcosystem are the commands that fetch a package from a registry and
// run it. `node`, `python`, a bare binary or `docker` run what is already on
// disk (or, for docker, are image pinning's concern).
var runnerEcosystem = map[string]string{
	"npx": EcosystemNPM, "pnpx": EcosystemNPM, "bunx": EcosystemNPM,
	"uvx": EcosystemPyPI, "pipx": EcosystemPyPI,
}

// packageFlagsWithValue are runner flags whose NEXT argument is the package.
var packageFlagsWithValue = map[string]bool{"-p": true, "--package": true, "--from": true}

// RunnerOf returns the package runner a command names (`/usr/local/bin/npx`,
// `npx.cmd`) and the ecosystem it fetches from.
func RunnerOf(command string) (runner, ecosystem string, ok bool) {
	r := strings.ToLower(command)
	r = r[strings.LastIndexAny(r, `/\`)+1:]
	r = strings.TrimSuffix(r, ".cmd")
	r = strings.TrimSuffix(r, ".exe")
	eco, ok := runnerEcosystem[r]
	return r, eco, ok
}

// PackageArgument picks the package out of a runner's arguments: the value of
// -p/--package/--from when given, otherwise the first argument that is not a
// flag. The second return is false when there is none (`npx --help`).
func PackageArgument(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if packageFlagsWithValue[a] {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		}
		if v, ok := strings.CutPrefix(a, "--package="); ok {
			return v, true
		}
		if v, ok := strings.CutPrefix(a, "--from="); ok {
			return v, true
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a, true
	}
	return "", false
}

// PackageIsPinned reports whether a package specifier names an exact version:
// npm's `name@1.2.3` / `@scope/name@1.2.3`, or pip's `name==1.2.3` /
// `name@1.2.3`. A dist-tag (`@latest`, `@next`), a range (`^1.2`, `~1`, `1.x`,
// `>=1`) and no version at all are all "whatever the registry says today".
func PackageIsPinned(spec string) bool {
	if name, v, ok := strings.Cut(spec, "=="); ok && name != "" {
		return exactVersionRe.MatchString(v)
	}
	at := strings.LastIndex(spec, "@")
	if at <= 0 { // no "@", or only the scope's leading one
		return false
	}
	return exactVersionRe.MatchString(spec[at+1:])
}

// PackageRef is the registry package an MCP server launch runs.
type PackageRef struct {
	Ecosystem string // EcosystemNPM or EcosystemPyPI
	Name      string // as written, without version or extras
	// Version is the exact version when Pinned, otherwise "".
	Version string
	Pinned  bool
	// Spec is the specifier as written (`@scope/server@1.2.3`).
	Spec string
}

// PackageOf reads the package a launch fetches from a registry. ok is false for
// anything else: a binary on disk, docker, a URL or git source, a local path, or
// a runner with no package argument. Those have no registry identity to look up.
func PackageOf(l Launch) (PackageRef, bool) {
	_, eco, ok := RunnerOf(l.Command)
	if !ok {
		return PackageRef{}, false
	}
	spec, ok := PackageArgument(l.Args)
	if !ok || spec == "" || strings.ContainsAny(spec, ":\\") || strings.HasPrefix(spec, ".") ||
		strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "~") {
		return PackageRef{}, false
	}
	ref := PackageRef{Ecosystem: eco, Spec: spec, Pinned: PackageIsPinned(spec)}
	switch eco {
	case EcosystemNPM:
		ref.Name = spec
		if at := strings.LastIndex(spec, "@"); at > 0 {
			ref.Name = spec[:at]
			if ref.Pinned {
				ref.Version = strings.TrimPrefix(spec[at+1:], "v")
			}
		}
	default:
		name := pipNameRe.FindString(spec)
		if name == "" {
			return PackageRef{}, false
		}
		ref.Name = name
		if ref.Pinned {
			_, v, _ := strings.Cut(spec, "==")
			if v == "" {
				v = spec[strings.LastIndex(spec, "@")+1:]
			}
			ref.Version = strings.TrimPrefix(v, "v")
		}
	}
	return ref, ref.Name != ""
}

// NormalizeName is the form in which two spellings of one package compare
// equal: npm names are case-insensitive lower-case, PyPI names follow PEP 503
// (lower-case, runs of `-`, `_` and `.` collapsed to one `-`).
func NormalizeName(ecosystem, name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if strings.EqualFold(ecosystem, EcosystemPyPI) {
		n = pipSepRe.ReplaceAllString(n, "-")
	}
	return n
}
