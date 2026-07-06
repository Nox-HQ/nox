package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// analyzePowerShellFile runs the full same-file pipeline (extraction +
// interprocedural AnalyzeFile) over PowerShell source, mirroring how taintflow
// drives the engine.
func analyzePowerShellFile(t *testing.T, src string) []string {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits("t.ps1", lexctx.LangPowerShell, []byte(src))
	flows := eng.AnalyzeFile(units)
	return ruleIDs(flows)
}

// TestStructuralPowerShellTruePositives exercises one representative flow per
// PowerShell vuln class end to end: an untrusted source ($args/$env/Read-Host)
// reaching a dangerous sink with no sanitizer must emit the catalog's rule ID.
func TestStructuralPowerShellTruePositives(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		wantID string
	}{
		{
			name:   "code injection via Invoke-Expression",
			src:    "$user = $args[0]\nInvoke-Expression $user\n",
			wantID: "TAINT-005",
		},
		{
			name:   "command injection via call operator",
			src:    "$cmd = $args[0]\n& $cmd\n",
			wantID: "TAINT-002",
		},
		{
			name:   "command injection via Start-Process",
			src:    "$name = $args[0]\nStart-Process -FilePath $name\n",
			wantID: "TAINT-002",
		},
		{
			name:   "sql injection via Invoke-Sqlcmd",
			src:    "$id = $args[0]\nInvoke-Sqlcmd -Query \"SELECT * FROM t WHERE id = $id\"\n",
			wantID: "TAINT-001",
		},
		{
			name:   "path traversal via Get-Content",
			src:    "$path = $args[0]\nGet-Content $path\n",
			wantID: "TAINT-004",
		},
		{
			name:   "path traversal via IO.File ReadAllText",
			src:    "$path = $args[0]\n$data = [IO.File]::ReadAllText($path)\n",
			wantID: "TAINT-004",
		},
		{
			name:   "ssrf via Invoke-WebRequest",
			src:    "$url = $args[0]\nInvoke-WebRequest -Uri $url\n",
			wantID: "TAINT-006",
		},
		{
			name:   "env source into Invoke-Expression",
			src:    "$e = $env:PAYLOAD\nInvoke-Expression $e\n",
			wantID: "TAINT-005",
		},
		{
			name:   "script param source into Get-Content",
			src:    "param([string]$Path)\n$p = $Path\nGet-Content $p\n",
			wantID: "TAINT-004",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ids := analyzePowerShellFile(t, tt.src)
			if !containsStr(ids, tt.wantID) {
				t.Errorf("want %s in findings, got %v", tt.wantID, ids)
			}
		})
	}
}

// TestStructuralPowerShellCleanStaysClean pins the precision-critical negatives:
// the sanitized / safe forms must fire nothing.
func TestStructuralPowerShellCleanStaysClean(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "int cast neutralizes command injection",
			src:  "$raw = $args[0]\n$id = [int]$raw\nStart-Process -FilePath \"tool-$id\"\n",
		},
		{
			name: "parameterized SqlCommand keeps tainted value out of query",
			src: "$id = $args[0]\n" +
				"$cmd = New-Object System.Data.SqlClient.SqlCommand\n" +
				"$cmd.CommandText = \"SELECT * FROM t WHERE id = @id\"\n" +
				"$cmd.Parameters.AddWithValue(\"@id\", $id)\n",
		},
		{
			name: "no source: constant command is safe",
			src:  "$name = \"report.txt\"\nGet-Content $name\n",
		},
		{
			name: "function parameter is not treated as a script source",
			src:  "function Read-Report ($ReportPath) {\n  Get-Content $ReportPath\n}\n",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ids := analyzePowerShellFile(t, tt.src)
			if len(ids) != 0 {
				t.Errorf("clean sample fired %v, want none", ids)
			}
		})
	}
}
