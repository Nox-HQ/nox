package core

import (
	"os"
	"path/filepath"
	"testing"
)

// A lockfile lists its authors' e-mail addresses by design. DATA-001 firing
// on every one of them is not sensitive data in code; it is the lockfile.
// The same address in a source file is still reported.
func TestScan_DataRulesDroppedOnLockfiles(t *testing.T) {
	dir := t.TempDir()
	lock := `{"packages":[{"name":"vendor/pkg","version":"1.0.0","authors":[{"name":"A","email":"maintainer@koel-app.io"}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.php"), []byte("<?php\n$owner = 'maintainer@koel-app.io';\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	var onLock, onSource int
	for _, f := range res.Findings.Findings() {
		if f.RuleID != "DATA-001" {
			continue
		}
		switch f.Location.FilePath {
		case "composer.lock":
			onLock++
		case "app.php":
			onSource++
		}
	}
	if onLock != 0 {
		t.Errorf("DATA-001 fired %d time(s) on composer.lock; a lockfile's author e-mails are not sensitive data in code", onLock)
	}
	if onSource == 0 {
		t.Errorf("DATA-001 did not fire on app.php; the drop must be scoped to generated paths, not the rule")
	}
}
