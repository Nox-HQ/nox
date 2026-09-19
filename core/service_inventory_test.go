package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/intel"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The service's own code decides reachability and capabilities; its tests do
// not. express is imported only by a test, and http.get appears only in one.
func TestDeriveServiceInventoryReadsTheServiceNotItsTests(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"package.json": `{"name":"checkout","version":"1.0.0","dependencies":{"lodash":"4.17.20","express":"4.18.2"}}`,
		"package-lock.json": `{"name":"checkout","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
 "":{"name":"checkout","version":"1.0.0","dependencies":{"lodash":"4.17.20","express":"4.18.2"}},
 "node_modules/lodash":{"version":"4.17.20"},
 "node_modules/express":{"version":"4.18.2"}}}`,
		"src/app.js": "const _ = require('lodash');\nconst cp = require('child_process');\n" +
			"function run(name) {\n  cp.exec('ls ' + _.trim(name));\n}\nmodule.exports = run;\n",
		"src/app.test.js": "const express = require('express');\nconst http = require('http');\n" +
			"function probe() {\n  http.get('http://127.0.0.1:1/health');\n}\n",
	})

	inv, err := DeriveServiceInventory(context.Background(), dir,
		intel.InventoryOptions{Service: "checkout", Exposed: true}, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	byPkg := map[string]intel.Component{}
	for _, c := range inv.Components {
		byPkg[c.Package] = c
	}
	if len(byPkg) != 2 {
		t.Fatalf("components %+v, want lodash and express from the lockfile", inv.Components)
	}
	if !byPkg["lodash"].VulnerablePathReachable || !byPkg["lodash"].ExternallyExposed {
		t.Errorf("lodash is imported by src/app.js: %+v", byPkg["lodash"])
	}
	if byPkg["express"].VulnerablePathReachable {
		t.Errorf("express is imported only by a test: %+v", byPkg["express"])
	}
	caps := map[string]intel.SinkSite{}
	for _, d := range inv.Derived {
		caps[d.Capability] = d.Evidence
	}
	if ev, ok := caps["shell.execute"]; !ok || ev.File != "src/app.js" {
		t.Errorf("shell.execute should be derived from src/app.js, got %+v", inv.Derived)
	}
	if _, ok := caps["network.egress"]; ok {
		t.Errorf("network.egress was derived from test code: %+v", inv.Derived)
	}
}
