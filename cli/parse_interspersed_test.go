package main

import (
	"flag"
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
