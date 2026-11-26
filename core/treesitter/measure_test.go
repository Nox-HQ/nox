package treesitter

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMeasureCorpus is the harness behind DefaultBudget's figures and
// docs/benchmarks/2026-11-23-treesitter-budget: it parses every Python,
// JavaScript, TypeScript, TSX, Java, C#, PHP, Ruby and Kotlin file under NOX_TS_MEASURE and writes
// one tab-separated line per file to NOX_TS_MEASURE_OUT:
//
//	language  bytes  checks  µs  error-tree  path  stopped-at-error  µs-with-stop
//
// The first parse sets no bounds; the second stops at a certain error, as
// ParseFile does. Skipped unless NOX_TS_MEASURE is set.
func TestMeasureCorpus(t *testing.T) {
	root, outPath := os.Getenv("NOX_TS_MEASURE"), os.Getenv("NOX_TS_MEASURE_OUT")
	if root == "" || outPath == "" {
		t.Skip("set NOX_TS_MEASURE (a source tree) and NOX_TS_MEASURE_OUT (the output file)")
	}
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			t.Error(err)
		}
	}()
	p := newParser(t)
	ctx := context.Background()
	ext := map[string]string{".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
		".ts": "typescript", ".tsx": "tsx", ".java": "java",
		".cs": "csharp", ".php": "php", ".rb": "ruby", ".kt": "kotlin", ".kts": "kotlin"}
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		lang, ok := ext[strings.ToLower(filepath.Ext(path))]
		if !ok {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil || len(src) == 0 || len(src) > DefaultBudget.MaxBytes {
			return nil
		}
		start := time.Now()
		tree, err := p.Parse(ctx, lang, src)
		full := time.Since(start)
		if err != nil {
			_, werr := fmt.Fprintf(out, "ERR\t%s\t%d\t%v\t%s\n", lang, len(src), err, path)
			return werr
		}
		start = time.Now()
		_, serr := p.parse(ctx, lang, src, bounds{stopAtError: true})
		withStop := time.Since(start)
		if serr != nil && !errors.Is(serr, ErrRecovery) {
			t.Errorf("%s: the bounded parse failed where the unbounded one did not: %v", path, serr)
		}
		_, werr := fmt.Fprintf(out, "%s\t%d\t%d\t%d\t%v\t%s\t%v\t%d\n", lang, len(src), tree.Checks, full.Microseconds(),
			tree.HasError(), path, errors.Is(serr, ErrRecovery), withStop.Microseconds())
		return werr
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
}
