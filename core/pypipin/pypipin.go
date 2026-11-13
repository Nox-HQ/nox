// Package pypipin answers how a vulnerable Python package is moved to its
// fixed version, for the file the finding came from. It is the one answer a
// finding, nox fix plan, the MCP server and nox fix apply give.
//
// The only move nox makes itself is editing an exact pin in a requirements
// file: a text edit, which runs nothing. It used to run `pip install` instead,
// which installs into whatever environment pip resolves to and never touches
// the requirements file or lockfile the finding is about, so the finding could
// never go away. Everything else is manual and says why: a range is the
// operator's declared intent, a hash-pinned file needs its hashes regenerated,
// and a lockfile belongs to a resolver (uv, poetry, pipenv) that can build
// source distributions, which runs the package's own code.
//
// Reads and writes files only; never runs a package manager.
package pypipin

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Advice is the answer for one package in one file.
type Advice struct {
	// Command describes the edit nox fix apply makes, for display. Empty
	// when the fix is manual.
	Command string
	// Manual says why nox does not make the move and what to run instead.
	// Empty when Command is set.
	Manual string

	path     string
	original []byte
	edited   []byte
}

// Apply writes the edit. It refuses a manual fix, and a file that changed
// since the advice was read.
func (a Advice) Apply() error {
	if a.edited == nil {
		return fmt.Errorf("%s", a.Manual)
	}
	current, err := os.ReadFile(a.path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, a.original) {
		return fmt.Errorf("%s changed since nox read it; run nox scan again", filepath.Base(a.path))
	}
	info, err := os.Stat(a.path)
	if err != nil {
		return err
	}
	return os.WriteFile(a.path, a.edited, info.Mode().Perm())
}

// AdviceFor answers for pkg at version from, moving to to, in the file at
// path: the file the finding was reported against.
func AdviceFor(path, pkg, from, to string) Advice {
	name := filepath.Base(path)
	from, to = strings.TrimPrefix(from, "v"), strings.TrimPrefix(to, "v")
	switch {
	case name == "uv.lock":
		return manual(pkg, to, "uv.lock is uv's", "uv lock --upgrade-package "+pkg)
	case name == "poetry.lock":
		return manual(pkg, to, "poetry.lock is poetry's", "poetry update "+pkg)
	case name == "Pipfile.lock":
		return manual(pkg, to, "Pipfile.lock is pipenv's", "pipenv update "+pkg)
	case strings.HasSuffix(name, ".txt"):
		return requirementsAdvice(path, pkg, from, to)
	}
	return Advice{Manual: fmt.Sprintf("%s declares %s; nox edits exact pins in requirements files only. "+
		"Raise it to %s there and re-run nox scan.", name, pkg, to)}
}

func manual(pkg, to, owner, command string) Advice {
	return Advice{Manual: fmt.Sprintf("%s lockfile, and resolving it can build source distributions, which runs package code, "+
		"so nox does not run it. Move %s to %s with: %s, then re-run nox scan.", owner, pkg, to, command)}
}

// requirementLine is one requirement: optional extras, one comparator, the
// version, and whatever follows (markers, comments) kept verbatim.
var requirementLine = regexp.MustCompile(`^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\s*(?:\[[^\]]*\])?\s*)(==|===|~=|!=|>=|<=|<|>)(\s*)([^\s,;#\\]+)(.*)$`)

func requirementsAdvice(path, pkg, from, to string) Advice {
	raw, err := os.ReadFile(path) //nolint:gosec // the file the finding was reported against
	if err != nil {
		return Advice{Manual: fmt.Sprintf("nox could not read %s: %v", filepath.Base(path), err)}
	}
	file := filepath.Base(path)
	lines := strings.SplitAfter(string(raw), "\n")
	want := normalize(pkg)

	if hashed(lines) {
		return Advice{Manual: fmt.Sprintf("%s pins with hashes; editing the version would break them. "+
			"Regenerate it (pip-compile --generate-hashes --upgrade-package %s==%s), then re-run nox scan.", file, pkg, to)}
	}

	var other []string
	edited := false
	for i, line := range lines {
		body, eol := splitEOL(line)
		m := requirementLine.FindStringSubmatch(body)
		if len(m) < 8 || normalize(m[2]) != want {
			continue
		}
		op, version, rest := m[4], m[6], m[7]
		if op != "==" || strings.HasPrefix(strings.TrimSpace(rest), ",") {
			return Advice{Manual: fmt.Sprintf("%s in %s is not an exact pin (%s); the range is yours to decide. "+
				"Change it so it admits %s, then re-run nox scan.", pkg, file, strings.TrimSpace(body), to)}
		}
		if version != from {
			other = append(other, version)
			continue
		}
		lines[i] = m[1] + m[2] + m[3] + op + m[5] + to + rest + eol
		edited = true
	}
	if !edited {
		if len(other) > 0 {
			return Advice{Manual: fmt.Sprintf("%s pins %s at %s, not the %s the finding names; re-run nox scan.",
				file, pkg, strings.Join(other, ", "), from)}
		}
		return Advice{Manual: fmt.Sprintf("%s is not pinned in %s; it comes from another requirement. "+
			"Add %s>=%s there, or upgrade the package that requires it, then re-run nox scan.", pkg, file, pkg, to)}
	}
	return Advice{
		Command:  fmt.Sprintf("set %s==%s in %s", pkg, to, file),
		path:     path,
		original: raw,
		edited:   []byte(strings.Join(lines, "")),
	}
}

// hashed reports a requirements file whose pins carry hashes: --hash on any
// requirement, or --require-hashes.
func hashed(lines []string) bool {
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if strings.Contains(t, "--hash=") || strings.Contains(t, "--hash ") || strings.HasPrefix(t, "--require-hashes") {
			return true
		}
	}
	return false
}

func splitEOL(line string) (body, eol string) {
	switch {
	case strings.HasSuffix(line, "\r\n"):
		return line[:len(line)-2], "\r\n"
	case strings.HasSuffix(line, "\n"):
		return line[:len(line)-1], "\n"
	}
	return line, ""
}

var separators = regexp.MustCompile(`[-_.]+`)

// normalize is PEP 503 name normalization.
func normalize(name string) string { return separators.ReplaceAllString(strings.ToLower(name), "-") }

// PinnedVersion is the version an exact pin for pkg sets in the requirements
// file at path, read the same way AdviceFor reads it. False when the file is
// not a requirements file, pkg is not pinned exactly, or two pins disagree.
func PinnedVersion(path, pkg string) (string, bool) {
	if !strings.HasSuffix(filepath.Base(path), ".txt") {
		return "", false
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the file nox fix edited
	if err != nil {
		return "", false
	}
	want, found := normalize(pkg), ""
	for _, line := range strings.SplitAfter(string(raw), "\n") {
		body, _ := splitEOL(line)
		m := requirementLine.FindStringSubmatch(body)
		if len(m) < 8 || normalize(m[2]) != want {
			continue
		}
		if m[4] != "==" || (found != "" && found != m[6]) {
			return "", false
		}
		found = m[6]
	}
	return found, found != ""
}
