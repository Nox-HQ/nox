package main

import (
	"strings"
	"testing"
)

func TestCompletion_Bash(t *testing.T) {
	if !strings.Contains(bashCompletion, "_nox_completions") {
		t.Fatal("bash completion missing _nox_completions function")
	}
	if !strings.Contains(bashCompletion, "complete -F") {
		t.Fatal("bash completion missing complete registration")
	}
}

func TestCompletion_Zsh(t *testing.T) {
	if !strings.Contains(zshCompletion, "#compdef nox") {
		t.Fatal("zsh completion missing #compdef header")
	}
	if !strings.Contains(zshCompletion, "baseline") {
		t.Fatal("zsh completion missing baseline command")
	}
}

func TestCompletion_Fish(t *testing.T) {
	if !strings.Contains(fishCompletion, "complete -c nox") {
		t.Fatal("fish completion missing complete -c nox")
	}
	if !strings.Contains(fishCompletion, "diff") {
		t.Fatal("fish completion missing diff command")
	}
}

func TestCompletion_Powershell(t *testing.T) {
	if !strings.Contains(powershellCompletion, "Register-ArgumentCompleter") {
		t.Fatal("powershell completion missing Register-ArgumentCompleter")
	}
}

func TestCompletion_UnknownShell(t *testing.T) {
	code := runCompletion([]string{"invalid"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for unknown shell, got %d", code)
	}
}

func TestCompletion_NoArgs(t *testing.T) {
	code := runCompletion(nil)
	if code != 2 {
		t.Fatalf("expected exit code 2 for no args, got %d", code)
	}
}

func TestCompletion_AllShellsContainAllCommands(t *testing.T) {
	commands := []string{"scan", "show", "explain", "badge", "baseline", "diff", "watch", "completion", "annotate", "serve", "registry", "plugin", "version"}

	shells := map[string]string{
		"bash":       bashCompletion,
		"zsh":        zshCompletion,
		"fish":       fishCompletion,
		"powershell": powershellCompletion,
	}

	for shellName, script := range shells {
		for _, cmd := range commands {
			if !strings.Contains(script, cmd) {
				t.Errorf("%s completion missing command %q", shellName, cmd)
			}
		}
	}
}
