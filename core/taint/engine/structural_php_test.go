package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// analyzePHPFile runs the full same-file pipeline (extraction + interprocedural
// AnalyzeFile) over PHP source, mirroring how taintflow drives the engine.
func analyzePHPFile(t *testing.T, src string) []string {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits("t.php", lexctx.LangPHP, []byte(src))
	flows := eng.AnalyzeFile(units)
	return ruleIDs(flows)
}

// TestStructuralPHPTruePositives exercises one representative flow per PHP vuln
// class end to end: superglobal source → dangerous sink with no sanitizer must
// emit the catalog's rule ID.
func TestStructuralPHPTruePositives(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		wantID string
	}{
		{
			name: "command injection via system",
			src: `<?php
$cmd = $_GET['cmd'];
system("echo " . $cmd);`,
			wantID: "TAINT-002",
		},
		{
			name: "sql injection via mysqli_query concat",
			src: `<?php
$id = $_GET['id'];
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);`,
			wantID: "TAINT-001",
		},
		{
			name: "sql injection via pdo->query method",
			src: `<?php
$id = $_GET['id'];
$pdo->query("SELECT * FROM users WHERE id = " . $id);`,
			wantID: "TAINT-001",
		},
		{
			name: "path traversal / LFI via include",
			src: `<?php
$page = $_GET['page'];
include($page);`,
			wantID: "TAINT-004",
		},
		{
			name: "path traversal via readfile",
			src: `<?php
$f = $_GET['file'];
readfile($f);`,
			wantID: "TAINT-004",
		},
		{
			name: "ssrf via curl_exec setopt",
			src: `<?php
$url = $_GET['url'];
$ch = curl_init($url);
curl_exec($ch);`,
			wantID: "TAINT-006",
		},
		{
			name: "unsafe deserialization via unserialize",
			src: `<?php
$data = $_COOKIE['session'];
$obj = unserialize($data);`,
			wantID: "TAINT-005",
		},
		{
			name: "xss via echo of tainted",
			src: `<?php
$name = $_GET['name'];
echo $name;`,
			wantID: "TAINT-003",
		},
		{
			name: "code injection via eval",
			src: `<?php
$expr = $_POST['expr'];
eval($expr);`,
			wantID: "TAINT-005",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ids := analyzePHPFile(t, tt.src)
			if !containsStr(ids, tt.wantID) {
				t.Errorf("want %s in findings, got %v", tt.wantID, ids)
			}
		})
	}
}

// TestStructuralPHPCleanStaysClean pins the precision-critical negatives: the
// sanitized / safe forms must fire nothing.
func TestStructuralPHPCleanStaysClean(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "escapeshellarg sanitizes command injection",
			src: `<?php
$cmd = $_GET['cmd'];
$safe = escapeshellarg($cmd);
system("echo " . $safe);`,
		},
		{
			name: "htmlspecialchars sanitizes xss echo",
			src: `<?php
$name = $_GET['name'];
$safe = htmlspecialchars($name);
echo $safe;`,
		},
		{
			name: "intval sanitizes sql injection",
			src: `<?php
$raw = $_GET['id'];
$id = intval($raw);
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);`,
		},
		{
			name: "basename sanitizes path traversal",
			src: `<?php
$raw = $_GET['file'];
$f = basename($raw);
readfile($f);`,
		},
		{
			name: "no source means no flow",
			src: `<?php
$cmd = "ls -la";
system($cmd);`,
		},
		{
			name: "constant echo is not xss",
			src: `<?php
echo "hello world";`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ids := analyzePHPFile(t, tt.src)
			if len(ids) != 0 {
				t.Errorf("want zero findings, got %v", ids)
			}
		})
	}
}
