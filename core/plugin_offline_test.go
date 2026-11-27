package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
)

// TestRunScan_PluginHooksSeeOfflineAndReportEgress pins the two halves of how
// the offline guarantee reaches plugins: an offline scan's context says so in
// both hooks (the plugin host reads it to refuse network tools), and the
// network-declaring tools a hook reports ran reach the result, where the CLI
// prints them.
func TestRunScan_PluginHooksSeeOfflineAndReportEgress(t *testing.T) {
	for _, offline := range []bool{true, false} {
		t.Run(map[bool]string{true: "offline", false: "online"}[offline], func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"),
				[]byte("plugins:\n  required:\n    - nox/triage-agent\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("x = 1\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			var scanSaw, postSaw bool
			ScanPluginHook = func(ctx context.Context, _ string, _ []string) (*PluginScanOutput, error) {
				scanSaw = OfflineScan(ctx)
				return &PluginScanOutput{Egress: []PluginEgress{{Plugin: "a", Tool: "scan", Hosts: []string{"h1"}}}}, nil
			}
			PostScanPluginHook = func(ctx context.Context, result *ScanResult, _ string, _ []string) error {
				postSaw = OfflineScan(ctx)
				result.PluginEgress = append(result.PluginEgress, PluginEgress{Plugin: "b", Tool: "triage", Hosts: []string{"h2"}})
				result.Degradations = append(result.Degradations, Degradation{Kind: degrade.Plugin, Detail: "post-scan tool refused", Impact: "enrichments missing"})
				return nil
			}
			defer func() { ScanPluginHook, PostScanPluginHook = nil, nil }()

			res, err := RunScanWithOptions(dir, ScanOptions{Offline: offline})
			if err != nil {
				t.Fatalf("RunScan: %v", err)
			}
			if scanSaw != offline || postSaw != offline {
				t.Errorf("hooks saw offline scan=%v post=%v, want %v", scanSaw, postSaw, offline)
			}
			var got []string
			for _, e := range res.PluginEgress {
				got = append(got, e.Plugin+"/"+e.Tool)
			}
			if strings.Join(got, ",") != "a/scan,b/triage" {
				t.Errorf("PluginEgress = %v, want [a/scan b/triage]", got)
			}
			var degraded bool
			for _, d := range res.Degradations {
				if d.Detail == "post-scan tool refused" {
					degraded = true
				}
			}
			if !degraded {
				t.Errorf("a degradation the post-scan hook recorded did not reach the result: %+v", res.Degradations)
			}
		})
	}
}
