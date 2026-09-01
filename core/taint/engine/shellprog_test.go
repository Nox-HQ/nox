package engine

import "testing"

// The arg-vector exemption rests on the premise that a tainted value passed as
// its own argv element is never parsed by a shell. Naming a shell as the
// PROGRAM is how that premise fails.
func TestNamesShellProgram(t *testing.T) {
	shells := []string{
		`"sh"`, `'bash'`, `"zsh"`, `"dash"`, `"ksh"`, `"fish"`,
		`"/bin/sh"`, `"/usr/bin/bash"`, `'/bin/zsh'`,
		`"cmd"`, `"cmd.exe"`, `"powershell"`, `"pwsh"`, `"env"`,
		`"SH"`, `"/bin/BASH"`, // basename-matched, case-folded
		`["sh", "-c", cmd]`,           // argv vector head
		`[ "/bin/bash" , "-c", cmd ]`, // spacing
		`("sh", "-c", cmd)`,           // tuple form
	}
	for _, s := range shells {
		if !namesShellProgram(s) {
			t.Errorf("namesShellProgram(%s) = false, want true", s)
		}
	}

	notShells := []string{
		``, `"ls"`, `"git"`, `"/usr/bin/git"`, `"python3"`, `"node"`,
		`["ls", "-la", user]`, `["git", "log", user]`,
		// An identifier naming the program is UNKNOWN, not a shell. Guessing
		// would void the exemption for every call whose program is a variable.
		`prog`, `argv[0]`, `cmd`,
		// A shell name inside a later argument is not the program.
		`["git", "commit", "-m", "use sh -c here"]`,
	}
	for _, s := range notShells {
		if namesShellProgram(s) {
			t.Errorf("namesShellProgram(%s) = true, want false", s)
		}
	}
}

func TestShellBasename(t *testing.T) {
	for in, want := range map[string]string{
		"/bin/sh": "sh", "sh": "sh", `C:\Windows\cmd.exe`: "cmd.exe",
		"/usr/local/bin/BASH": "bash", "": "",
	} {
		if got := shellBasename(in); got != want {
			t.Errorf("shellBasename(%q) = %q, want %q", in, got, want)
		}
	}
}

// A program named by an identifier is unknown. Reading it as a shell would void
// the exemption wherever the program is a variable, turning every safe argv exec
// back into a finding.
func TestUnquotedProgramIsNotAShell(t *testing.T) {
	if unquoteLiteral("prog") != "" {
		t.Error("an identifier was read as a quoted literal")
	}
	if namesShellProgram("[prog, \"-c\", cmd]") {
		t.Error("a variable program name was treated as a shell")
	}
}
