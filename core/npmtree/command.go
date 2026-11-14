package npmtree

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Command is the command nox fix apply runs to move pkg to version in dir:
// the package manager picked from the lockfile, the section and specifier
// style package.json already uses, and `npm update` for a package
// package.json does not list.
//
// "npm" is an OSV ecosystem, not a tool: the same ecosystem is served by npm,
// pnpm, yarn and bun, and they do not share a lockfile. Running `npm install`
// in a pnpm workspace writes a package-lock.json next to the pnpm-lock.yaml
// and resolves a tree the workspace will never install from.
//
// pnpm gets --depth Infinity because most advisories land on transitive
// dependencies, which a default-depth update does not reach.
func Command(dir, pkg, version string) (tool string, args []string) {
	target := pkg + "@" + version
	has := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	section, spec, _ := Declaration(dir, pkg)
	style := styleOfSpec(spec)
	// The fix is a version in package.json and the lockfile. Where the project
	// has no node_modules, installing would create one, full of third-party
	// READMEs and fixtures that the next scan reports as findings; npm and
	// pnpm can rewrite the lockfile alone. Where node_modules exists it is
	// kept in step, or the installed tree would no longer match the lockfile.
	lockOnly := !has("node_modules")
	// Every command here installs packages, and installing runs their
	// lifecycle scripts: arbitrary code from whatever version nox just chose.
	// nox never executes untrusted code, so scripts are always off.
	switch {
	case has("pnpm-lock.yaml"):
		a := []string{"update", "--ignore-scripts", "--depth", "Infinity"}
		if lockOnly {
			a = append(a, "--lockfile-only")
		}
		return "pnpm", append(a, target)
	case has("yarn.lock"):
		// Berry renamed the verb and is told apart by its own config file.
		// Berry has no --ignore-scripts on `up`; nox fix sets
		// YARN_ENABLE_SCRIPTS=false for it.
		if has(".yarnrc.yml") {
			return "yarn", append(append([]string{"up"}, saveFlags("yarn", style)...), target)
		}
		return "yarn", append(append([]string{"upgrade", "--ignore-scripts"}, saveFlags("yarn", style)...), target)
	case has("bun.lock"), has("bun.lockb"):
		// bun has no lockfile-only update (bun 1.1: even `install
		// --lockfile-only` creates node_modules), so it always installs.
		return "bun", []string{"update", "--ignore-scripts", target}
	}
	// npm install writes whatever it is given into package.json: a transitive
	// package becomes a new direct dependency, and a devDependency moves into
	// dependencies. So the manifest decides. A declared package keeps its
	// section; anything else is moved by `npm update`, which touches only the
	// lockfile and takes no version — nox fix reads the lockfile back to see where it landed.
	npmArgs := func(verb string) []string {
		a := []string{verb, "--ignore-scripts"}
		if lockOnly {
			a = append(a, "--package-lock-only")
		}
		return a
	}
	install := func(extra ...string) []string {
		a := append(npmArgs("install"), extra...)
		a = append(a, saveFlags("npm", style)...)
		return append(a, target)
	}
	switch section {
	case "dependencies":
		return "npm", install()
	case "devDependencies":
		return "npm", install("--save-dev")
	case "optionalDependencies":
		return "npm", install("--save-optional")
	}
	return "npm", append(npmArgs("update"), pkg)
}

// specStyle is how a package.json specifier pins a version.
type specStyle int

const (
	// styleOther covers ranges, wildcards, tags and non-registry sources. The
	// package manager's own default applies; nox has no faithful way to keep
	// them.
	styleOther specStyle = iota
	styleExact
	styleCaret
	styleTilde
)

// styleOfSpec classifies a specifier so an upgrade can keep the operator's
// choice. An exact pin is a decision (reproducible builds, a vetted version),
// and rewriting it to a caret range silently widens what any later install
// may resolve.
func styleOfSpec(spec string) specStyle {
	spec = strings.TrimSpace(spec)
	switch {
	case strings.HasPrefix(spec, "^"):
		return styleCaret
	case strings.HasPrefix(spec, "~"):
		return styleTilde
	case exactVersionRE.MatchString(spec):
		return styleExact
	}
	return styleOther
}

var exactVersionRE = regexp.MustCompile(`^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.+-]+)?$`)

// saveFlags are the npm/yarn flags that make a written specifier match style.
// styleOther gets none: the manager's default is the best nox can do.
func saveFlags(tool string, style specStyle) []string {
	switch tool {
	case "npm":
		switch style {
		case styleExact:
			return []string{"--save-exact"}
		case styleTilde:
			return []string{"--save-prefix=~"}
		case styleCaret:
			return []string{"--save-prefix=^"}
		}
	case "yarn":
		switch style {
		case styleExact:
			return []string{"--exact"}
		case styleTilde:
			return []string{"--tilde"}
		case styleCaret:
			return []string{"--caret"}
		}
	}
	// pnpm and bun keep the existing specifier's style when given an explicit
	// version (measured, pnpm 10.24 and bun 1.x), so they need nothing.
	return nil
}

// Advice is the one answer to "how is pkg moved to fixed here" that a
// finding, nox fix plan, the MCP server and nox fix apply all give.
type Advice struct {
	// Command is what nox fix apply runs, as a shell line. Empty when the
	// lockfile shows a parent holds the package: no command can move it.
	Command string
	// Transitive is set when package.json establishes that the project does
	// not list pkg itself.
	Transitive bool
	// Reach is the lockfile's account of the move, for a transitive package.
	Reach Reach
}

// AdviceFor answers for pkg in dir, reading the workspace for one question.
func AdviceFor(dir, pkg, fixed string) Advice { return Open(dir).Advice(pkg, fixed) }

// Advice answers for pkg in this workspace.
func (p *Project) Advice(pkg, fixed string) Advice {
	version := strings.TrimPrefix(fixed, "v")
	tool, args := Command(p.dir, pkg, version)
	adv := Advice{Command: tool + " " + strings.Join(args, " ")}
	if !Transitive(p.dir, pkg) {
		return adv
	}
	adv.Transitive = true
	adv.Reach = p.Reach(pkg, version)
	if adv.Reach.Held() {
		adv.Command = ""
	}
	return adv
}
