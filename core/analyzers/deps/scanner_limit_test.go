package deps

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"
)

// bufio.Scanner stops at a 64 KiB line and reports ErrTooLong through Err().
// A parser that neither raises the limit nor checks Err() therefore stops
// reading at that line and returns what it had — a truncated dependency list
// that looks exactly like a complete one. Everything after the long line is
// missing from the SBOM and from vulnerability matching, silently.
//
// The package already knew this: maxLockfileLine exists in parsers_ecosystem.go
// with a comment saying the scanner "stops silently at that limit, which would
// truncate the dependency list without any error". It was applied to three
// scanners out of seventeen.
//
// Long lines in real manifests are not exotic. A vendored one-line JSON blob, a
// generated requirements file, a Gemfile.lock with a very long git URL set, a
// Dockerfile with one enormous RUN — any of them reaches 64 KiB.

// longLine returns a comment line safely over the 64 KiB scanner limit.
func longLine(prefix string) string {
	return prefix + strings.Repeat("x", 70*1024)
}

// TestParsersSurviveALineOverTheScannerLimit pins that content AFTER a very
// long line is still parsed. The entry before it is what makes the test
// meaningful: a parser that returned nothing at all would be obviously broken,
// whereas one that returns the first half looks like it worked.
func TestParsersSurviveALineOverTheScannerLimit(t *testing.T) {
	tests := []struct {
		name    string
		content string
		parse   func([]byte) ([]Package, error)
		want    string
	}{
		{
			name: "go.mod",
			content: "module example.com/m\n\ngo 1.22\n\nrequire (\n" +
				"\tbefore.example/a v1.0.0\n" +
				"\t// " + longLine("") + "\n" +
				"\tafter.example/b v2.0.0\n)\n",
			parse: parseGoMod,
			want:  "after.example/b",
		},
		{
			name: "requirements.txt",
			content: "before-pkg==1.0.0\n" +
				"# " + longLine("") + "\n" +
				"after-pkg==2.0.0\n",
			parse: parseRequirementsTxt,
			want:  "after-pkg",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.parse([]byte(tc.content))
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			var names []string
			for _, p := range got {
				names = append(names, p.Name)
			}
			joined := strings.Join(names, ",")
			if !strings.Contains(joined, tc.want) {
				t.Errorf("%s: parsing stopped at the over-long line — %q is missing from %v. "+
					"Every dependency after that point is absent from the SBOM and from "+
					"vulnerability matching, with no error to say so", tc.name, tc.want, names)
			}
		})
	}
}

// TestDockerfileSurvivesALineOverTheScannerLimit covers the container parser,
// where one very long RUN is entirely ordinary.
func TestDockerfileSurvivesALineOverTheScannerLimit(t *testing.T) {
	content := "FROM alpine:3.19\n" +
		"RUN " + longLine("") + "\n" +
		"FROM debian:12 AS final\n"

	got, err := ParseDockerfile([]byte(content))
	if err != nil {
		t.Fatalf("parsing Dockerfile: %v", err)
	}
	var images []string
	for _, p := range got {
		images = append(images, p.Name)
	}
	if !strings.Contains(strings.Join(images, ","), "debian") {
		t.Errorf("parsing stopped at the over-long RUN — the debian base image is missing from %v, "+
			"so a vulnerable base image goes unreported", images)
	}
}

// TestEveryLineScannerRaisesTheLimit stops the defect returning. A raw
// bufio.NewScanner in this package is a parser that truncates at 64 KiB, and
// the truncation is silent, so nothing else will notice.
//
// The package already knew the rule and applied it to three scanners out of
// seventeen. A comment explaining a hazard does not enforce it; this does.
func TestEveryLineScannerRaisesTheLimit(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package dir: %v", err)
	}

	var checked int
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "linescan.go" {
			continue
		}
		raw, err := os.ReadFile(name) //nolint:gosec // this package's own source
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		checked++
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, "bufio.NewScanner(") {
				t.Errorf("%s:%d uses bufio.NewScanner directly. Its 64 KiB line limit ends the scan "+
					"silently, truncating the result rather than failing it. Use newLineScanner.",
					name, i+1)
			}
		}
	}
	if checked == 0 {
		t.Fatal("scanned no package sources; the guard is vacuous")
	}
}

// TestLineScannerLimitIsActuallyRaised proves the helper does what its name
// says, so the guard above is not merely enforcing a naming convention.
func TestLineScannerLimitIsActuallyRaised(t *testing.T) {
	long := strings.Repeat("y", 70*1024)
	sc := newLineScanner(strings.NewReader(long + "\nsecond\n"))

	if !sc.Scan() {
		t.Fatalf("the scanner refused a %d-byte line: %v", len(long), sc.Err())
	}
	if !sc.Scan() || sc.Text() != "second" {
		t.Errorf("the line after a %d-byte line was not read (err: %v)", len(long), sc.Err())
	}
	if err := sc.Err(); err != nil {
		t.Errorf("scanning reported %v", err)
	}

	// And the raised limit is finite, so a pathological file cannot exhaust
	// memory: past it the scanner must fail loudly rather than truncate.
	huge := strings.Repeat("z", maxLockfileLine+1024)
	over := newLineScanner(strings.NewReader(huge))
	if over.Scan() {
		t.Error("a line past maxLockfileLine was accepted; the bound does not hold")
	}
	if !errors.Is(over.Err(), bufio.ErrTooLong) {
		t.Errorf("a line past the bound reported %v, want bufio.ErrTooLong so a caller can tell "+
			"truncation from a clean end of file", over.Err())
	}
}
