package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

// FuzzScanArtifacts fuzzes file content through the secrets analyzer pipeline.
// This tests the full analyzer path including entropy detection, regex matching,
// and all 160+ secret detection rules.
func FuzzScanArtifacts(f *testing.F) {
	// nox:ignore SEC-001,SEC-078,SEC-100 -- fuzz seed corpus with intentional security patterns
	f.Add([]byte("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))
	f.Add([]byte("AKIAIOSFODNN7EXAMPLE"))
	f.Add([]byte("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"))
	f.Add([]byte("password: supersecret123"))
	f.Add([]byte("normal code without secrets"))
	f.Add([]byte(""))
	f.Add([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIE..."))

	f.Fuzz(func(t *testing.T, content []byte) {
		dir := t.TempDir()
		testFile := filepath.Join(dir, "fuzz_input.txt")
		if err := os.WriteFile(testFile, content, 0o644); err != nil {
			return
		}

		analyzer := NewAnalyzer()
		artifacts := []discovery.Artifact{
			{
				Path:    "fuzz_input.txt",
				AbsPath: testFile,
				Type:    discovery.Source,
			},
		}

		// Must not panic regardless of input.
		_, _ = analyzer.ScanArtifacts(context.Background(), artifacts)
	})
}
