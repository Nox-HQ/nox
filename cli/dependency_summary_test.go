package main

import (
	"strings"
	"testing"

	nox "github.com/nox-hq/nox/core"
)

func TestDependencySummary(t *testing.T) {
	gap := []nox.Degradation{{Kind: "lockfile_parse"}}
	other := []nox.Degradation{{Kind: "plugin"}}
	tests := []struct {
		name    string
		count   int
		scanned bool
		degs    []nox.Degradation
		want    string
	}{
		{"not scanned", 0, false, nil, "dependencies not scanned"},
		{"none and nothing unread", 0, true, nil, "0 dependencies"},
		{"unrelated degradation", 3, true, other, "3 dependencies"},
		{"manifest not read", 0, true, gap, "NOT checked"},
		{"partly read", 2, true, gap, "2 dependencies checked"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dependencySummary(tc.count, tc.scanned, tc.degs)
			if !strings.Contains(got, tc.want) {
				t.Errorf("dependencySummary = %q, want it to contain %q", got, tc.want)
			}
			if tc.degs != nil && string(tc.degs[0].Kind) == "lockfile_parse" && got == "0 dependencies" {
				t.Errorf("an unread manifest reads as %q", got)
			}
		})
	}
}
