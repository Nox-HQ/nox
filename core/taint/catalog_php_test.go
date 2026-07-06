package taint

import "testing"

// TestPHPCatalogSinks asserts the PHP language block carries the sinks the
// precision corpus annotations require, with the exact rule_id/cwe/vuln_class the
// tp_*.php samples expect.
func TestPHPCatalogSinks(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name      string
		call      string
		wantClass VulnClass
		wantCWE   string
		wantRule  string
	}{
		{"system cmdi", "system", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"shell_exec cmdi", "shell_exec", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"exec cmdi", "exec", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"mysqli_query sqli", "mysqli_query", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"pdo.query sqli", "pdo.query", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"include path", "include", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"readfile path", "readfile", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"curl_exec ssrf", "curl_exec", VulnSSRF, "CWE-918", "TAINT-006"},
		{"unserialize deser", "unserialize", VulnUnsafeDeserialization, "CWE-502", "TAINT-005"},
		{"echo xss", "echo", VulnXSS, "CWE-79", "TAINT-003"},
		{"eval code", "eval", VulnCodeInjection, "CWE-95", "TAINT-005"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, ok := cat.IsSink("php", tt.call)
			if !ok {
				t.Fatalf("IsSink(php, %q) = false, want true", tt.call)
			}
			if sink.VulnClass != tt.wantClass {
				t.Errorf("VulnClass = %q, want %q", sink.VulnClass, tt.wantClass)
			}
			if sink.CWE != tt.wantCWE {
				t.Errorf("CWE = %q, want %q", sink.CWE, tt.wantCWE)
			}
			if sink.RuleID != tt.wantRule {
				t.Errorf("RuleID = %q, want %q", sink.RuleID, tt.wantRule)
			}
		})
	}
}

// TestPHPCatalogSources asserts the superglobal untrusted-input sources are
// present. They are keyed by the sigil-stripped name (`_GET`, not `$_GET`) the
// extractor produces after normalization.
func TestPHPCatalogSources(t *testing.T) {
	cat := MustDefault()
	for _, call := range []string{"_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER"} {
		if !cat.IsSource("php", call) {
			t.Errorf("IsSource(php, %q) = false, want true", call)
		}
	}
}

// TestPHPCatalogSanitizers asserts each PHP sanitizer neutralizes the classes the
// clean corpus stressors rely on.
func TestPHPCatalogSanitizers(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		call  string
		class VulnClass
	}{
		{"escapeshellarg", VulnCommandInjection},
		{"escapeshellcmd", VulnCommandInjection},
		{"mysqli_real_escape_string", VulnSQLInjection},
		{"htmlspecialchars", VulnXSS},
		{"htmlentities", VulnXSS},
		{"intval", VulnSQLInjection},
		{"basename", VulnPathTraversal},
	}
	for _, tt := range tests {
		if !cat.IsSanitizer("php", tt.call, tt.class) {
			t.Errorf("IsSanitizer(php, %q, %q) = false, want true", tt.call, tt.class)
		}
	}
}
