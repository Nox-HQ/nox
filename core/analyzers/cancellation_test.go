// Package analyzers_test verifies that every analyzer honours context
// cancellation between artifacts.
//
// All four analyzers accepted a context and then ignored it: only the deps
// analyzer ever consulted ctx, so a cancelled scan kept reading files until the
// walk finished. On a large tree that meant cancellation was effectively
// ignored, while the pipeline's doc comment claimed the context was propagated
// to every analyzer.
package analyzers_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/data"
	"github.com/nox-hq/nox/core/analyzers/iac"
	"github.com/nox-hq/nox/core/analyzers/secrets"
	"github.com/nox-hq/nox/core/discovery"
)

// buildArtifacts writes n small files and returns artifacts describing them.
// Several files are needed because cancellation is checked between artifacts.
func buildArtifacts(t *testing.T, n int) []discovery.Artifact {
	t.Helper()

	dir := t.TempDir()
	artifacts := make([]discovery.Artifact, 0, n)
	for i := range n {
		name := filepath.Join(dir, "file.tf")
		if i > 0 {
			name = filepath.Join(dir, "file"+string(rune('a'+i))+".tf")
		}
		content := []byte("resource \"aws_s3_bucket\" \"b\" {}\n")
		if err := os.WriteFile(name, content, 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		artifacts = append(artifacts, discovery.Artifact{
			Path:    filepath.Base(name),
			AbsPath: name,
			Size:    int64(len(content)),
		})
	}
	return artifacts
}

func TestAnalyzers_HonourCancellation(t *testing.T) {
	t.Parallel()

	artifacts := buildArtifacts(t, 8)

	// Already-cancelled context: every analyzer must give up rather than
	// working through the artifact list.
	tests := []struct {
		name string
		scan func(ctx context.Context) error
	}{
		{"secrets", func(ctx context.Context) error {
			_, err := secrets.NewAnalyzer().ScanArtifacts(ctx, artifacts)
			return err
		}},
		{"data", func(ctx context.Context) error {
			_, err := data.NewAnalyzer().ScanArtifacts(ctx, artifacts)
			return err
		}},
		{"iac", func(ctx context.Context) error {
			_, err := iac.NewAnalyzer().ScanArtifacts(ctx, artifacts)
			return err
		}},
		{"ai", func(ctx context.Context) error {
			_, _, err := ai.NewAnalyzer().ScanArtifacts(ctx, artifacts)
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			if err := tt.scan(ctx); err == nil {
				t.Error("expected a cancellation error, got nil — the analyzer ignores ctx")
			} else if !errorIsCancelled(err) {
				t.Errorf("expected context.Canceled, got %v", err)
			}
		})
	}
}

func TestAnalyzers_RunToCompletionWithLiveContext(t *testing.T) {
	t.Parallel()

	// The cancellation check must not break the normal path.
	artifacts := buildArtifacts(t, 3)
	ctx := context.Background()

	if _, err := secrets.NewAnalyzer().ScanArtifacts(ctx, artifacts); err != nil {
		t.Errorf("secrets: %v", err)
	}
	if _, err := data.NewAnalyzer().ScanArtifacts(ctx, artifacts); err != nil {
		t.Errorf("data: %v", err)
	}
	if _, err := iac.NewAnalyzer().ScanArtifacts(ctx, artifacts); err != nil {
		t.Errorf("iac: %v", err)
	}
	if _, _, err := ai.NewAnalyzer().ScanArtifacts(ctx, artifacts); err != nil {
		t.Errorf("ai: %v", err)
	}
}

func errorIsCancelled(err error) bool {
	return err == context.Canceled || err.Error() == context.Canceled.Error()
}
