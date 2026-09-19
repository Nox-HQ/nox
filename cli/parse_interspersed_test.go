package main

import (
	"flag"
	"strings"
	"testing"
)

// parseInterspersed must honor flags placed before AND after positional
// arguments, since the stdlib flag package stops parsing at the first
// positional (the cause of #103: `nox scan . -severity-threshold high`
// silently dropped the flag).
func TestParseInterspersed(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantPath  string
		wantSev   string
		wantBool  bool
		wantPosln int
	}{
		{
			name:      "flags before path",
			args:      []string{"-severity-threshold", "high", "-offline", "."},
			wantPath:  ".",
			wantSev:   "high",
			wantBool:  true,
			wantPosln: 1,
		},
		{
			name:      "flags after path (the #103 case)",
			args:      []string{".", "-severity-threshold", "high", "-offline"},
			wantPath:  ".",
			wantSev:   "high",
			wantBool:  true,
			wantPosln: 1,
		},
		{
			name:      "flags interspersed around path",
			args:      []string{"-offline", "src", "-severity-threshold", "critical"},
			wantPath:  "src",
			wantSev:   "critical",
			wantBool:  true,
			wantPosln: 1,
		},
		{
			name:      "path only",
			args:      []string{"."},
			wantPath:  ".",
			wantSev:   "",
			wantBool:  false,
			wantPosln: 1,
		},
		{
			name:      "value flag then path",
			args:      []string{"-severity-threshold", "low", "dir", "-offline"},
			wantPath:  "dir",
			wantSev:   "low",
			wantBool:  true,
			wantPosln: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("scan", flag.ContinueOnError)
			var sev string
			var offline bool
			fs.StringVar(&sev, "severity-threshold", "", "")
			fs.BoolVar(&offline, "offline", false, "")

			positionals, err := parseInterspersed(fs, tt.args)
			if err != nil {
				t.Fatalf("parseInterspersed: %v", err)
			}
			if len(positionals) != tt.wantPosln {
				t.Fatalf("positionals = %v, want %d", positionals, tt.wantPosln)
			}
			if positionals[0] != tt.wantPath {
				t.Errorf("path = %q, want %q", positionals[0], tt.wantPath)
			}
			if sev != tt.wantSev {
				t.Errorf("severity-threshold = %q, want %q (flag dropped?)", sev, tt.wantSev)
			}
			if offline != tt.wantBool {
				t.Errorf("offline = %v, want %v (flag dropped?)", offline, tt.wantBool)
			}
		})
	}
}

func TestParseInterspersed_InvalidFlag(t *testing.T) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(discardWriter{})
	fs.Bool("offline", false, "")
	if _, err := parseInterspersed(fs, []string{".", "-nope"}); err == nil {
		t.Error("expected error for unknown flag, got nil")
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// `--` ends flag parsing for good. `nox mcp baseline -- nox serve
// --allowed-paths x` hands everything after it to a child command; re-parsing
// that tail as our own flags would either reject the child's flags as unknown
// or, worse, consume one that happens to share a name.
func TestParseInterspersedStopsAtDoubleDash(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	out := fs.String("output", "", "")
	pos, err := parseInterspersed(fs, []string{"--output", "o", "--", "nox", "serve", "--output", "child", "-x"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *out != "o" {
		t.Errorf("--output = %q, want o (the child's --output must not reach us)", *out)
	}
	want := []string{"nox", "serve", "--output", "child", "-x"}
	if strings.Join(pos, " ") != strings.Join(want, " ") {
		t.Errorf("positionals = %q, want %q verbatim", pos, want)
	}

	// A flag after a positional but before `--` is still ours.
	fs2 := flag.NewFlagSet("t", flag.ContinueOnError)
	out2 := fs2.String("output", "", "")
	pos2, err := parseInterspersed(fs2, []string{"a", "--output", "o", "--", "--output", "child"})
	if err != nil || *out2 != "o" || strings.Join(pos2, " ") != "a --output child" {
		t.Errorf("got output=%q pos=%q err=%v", *out2, pos2, err)
	}
}

// The #103 class, through real commands. `nox registry add <url> --name x` is
// the order `registry add`'s own usage line gives, and it used to drop --name
// silently and file the registry under the URL's hostname.
func TestRegistryAddHonoursNameAfterTheURL(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NOX_NO_DEFAULT_REGISTRY", "1")
	const u = "https://example.invalid/index.json"
	if code := runRegistryAdd([]string{u, "--name", "official"}); code != 0 {
		t.Fatalf("registry add exit %d", code)
	}
	out := captureStdout(t, func() { runRegistryList(nil) })
	if !strings.Contains(out, "official") || strings.Contains(out, "example.invalid  ") {
		t.Errorf("--name after the URL was ignored:\n%s", out)
	}
}

func TestPluginTestHonoursTrackAfterTheBinary(t *testing.T) {
	bin := buildPluginFixture(t, "netplugin")
	// Under core-analysis the network host is refused (exit 1). If --track
	// were dropped, no track could be inferred and the exit would be 2.
	if code := runPluginTest([]string{bin, "--track", "core-analysis", "--target", t.TempDir()}); code != 1 {
		t.Fatalf("exit %d, want 1: --track after the binary was not honoured", code)
	}
}
