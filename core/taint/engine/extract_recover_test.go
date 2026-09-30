package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractUnitsRecoversFromAPanic: a defect in one file's extraction costs
// that file's flows, not the scan.
func TestExtractUnitsRecoversFromAPanic(t *testing.T) {
	orig := extractUnitsFn
	t.Cleanup(func() { extractUnitsFn = orig })
	extractUnitsFn = func(lexctx.Lang, []byte) []unitDraft { panic("boom") }

	before := ExtractPanics()
	if units := ExtractUnits("a.php", lexctx.LangPHP, []byte("<?php echo $x;")); units != nil {
		t.Fatalf("units = %v, want nil", units)
	}
	if ExtractPanics() != before+1 {
		t.Fatalf("panic not counted")
	}
}
