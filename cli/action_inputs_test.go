package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// action.yml declares inputs; action.sh consumes them as INPUT_<UPPER_SNAKE>
// environment variables that action.yml's `env:` block has to map. Nothing
// connects the two halves automatically, so an input can be declared and
// documented while never reaching the scanner — the step accepts it, the flag
// is silently dropped, and a workflow that sets it is not doing what it says.
//
// `fail-on-degraded` was missing this way round: nox has had the flag since
// 1.11.0, the Action never exposed it, so a CI job could not make "a check did
// not complete" fail the build without dropping to a raw run step.
func TestActionInputsAreWiredToTheScript(t *testing.T) {
	yml := readActionFile(t, "action.yml")
	sh := readActionFile(t, "action.sh")

	declared := declaredInputs(t, yml)
	if len(declared) == 0 {
		t.Fatal("parsed no inputs from action.yml — the parser or the file layout changed")
	}

	envBlock := actionEnvBlock(t, yml)

	for _, name := range declared {
		envVar := "INPUT_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))

		if !strings.Contains(envBlock, envVar+":") {
			t.Errorf("input %q is declared in action.yml but never mapped to %s in the env: block, so action.sh cannot see it", name, envVar)
			continue
		}
		if !strings.Contains(sh, envVar) {
			t.Errorf("input %q reaches action.sh as %s but the script never reads it", name, envVar)
		}
	}
}

// The flag exists in nox and the Action now exposes it; this pins the specific
// wiring so a refactor of the argument assembly cannot quietly drop it.
func TestActionPassesFailOnDegraded(t *testing.T) {
	yml := readActionFile(t, "action.yml")
	sh := readActionFile(t, "action.sh")

	if !strings.Contains(yml, "fail-on-degraded:") {
		t.Error("action.yml does not declare a fail-on-degraded input; CI cannot fail on an incomplete scan without a raw run step")
	}
	if !strings.Contains(sh, "--fail-on-degraded") {
		t.Error("action.sh never appends --fail-on-degraded, so the input would be accepted and ignored")
	}
}

func readActionFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// declaredInputs returns the input names under action.yml's top-level
// `inputs:` key. Inputs are the only two-space-indented keys in that block;
// their attributes are indented four.
func declaredInputs(t *testing.T, yml string) []string {
	t.Helper()

	block := sectionAfter(yml, "inputs:")
	if block == "" {
		t.Fatal("action.yml has no inputs: block")
	}

	re := regexp.MustCompile(`(?m)^ {2}([a-z0-9-]+):`)
	var names []string
	for _, m := range re.FindAllStringSubmatch(block, -1) {
		names = append(names, m[1])
	}
	return names
}

// actionEnvBlock returns the `env:` mapping inside the composite run step.
func actionEnvBlock(t *testing.T, yml string) string {
	t.Helper()

	block := sectionAfter(yml, "      env:")
	if block == "" {
		t.Fatal("action.yml env: block is empty")
	}
	return block
}

// sectionAfter returns the lines following header up to the next line that
// starts at or left of header's own indentation.
func sectionAfter(s, header string) string {
	_, rest, found := strings.Cut(s, header)
	if !found {
		return ""
	}
	indent := len(header) - len(strings.TrimLeft(header, " "))

	var out []string
	for line := range strings.SplitSeq(rest, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lead := len(line) - len(strings.TrimLeft(line, " "))
		if lead <= indent {
			break
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
