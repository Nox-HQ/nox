package taint

import "testing"

// TestScalaCatalogSinks asserts the Scala language block carries the sinks the
// precision suite annotations require, with the exact rule_id/cwe/vuln_class the
// tp_*.scala samples expect.
func TestScalaCatalogSinks(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name      string
		call      string
		wantClass VulnClass
		wantCWE   string
		wantRule  string
	}{
		{"Process cmdi", "Process", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"exec cmdi", "exec", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"process-bang cmdi", ".!", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"executeQuery sqli", "executeQuery", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"execute sqli", "execute", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"sql interpolator sqli", "sql", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"Source.fromFile path", "Source.fromFile", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"File path", "File", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"Files.readAllBytes path", "Files.readAllBytes", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"openStream ssrf", "openStream", VulnSSRF, "CWE-918", "TAINT-006"},
		{"fromURL ssrf", "fromURL", VulnSSRF, "CWE-918", "TAINT-006"},
		{"ObjectInputStream deser", "ObjectInputStream", VulnUnsafeDeserialization, "CWE-502", "TAINT-005"},
		{"Html xss", "Html", VulnXSS, "CWE-79", "TAINT-003"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, ok := cat.IsSink("scala", tt.call)
			if !ok {
				t.Fatalf("IsSink(scala, %q) = false, want true", tt.call)
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

// TestScalaCatalogSources asserts the untrusted-input sources are present.
func TestScalaCatalogSources(t *testing.T) {
	cat := MustDefault()
	for _, call := range []string{
		"request.getQueryString", "request.queryString", "request.body",
		"getQueryString", "queryString", "params",
	} {
		if !cat.IsSource("scala", call) {
			t.Errorf("IsSource(scala, %q) = false, want true", call)
		}
	}
}

// TestScalaCatalogSanitizers asserts each sanitizer neutralizes exactly the
// class(es) its sink family needs: prepared statements defuse SQLi, HTML-escape
// defuses XSS, numeric coercion defuses the injection families, and File.getName
// defuses path traversal.
func TestScalaCatalogSanitizers(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		call  string
		class VulnClass
	}{
		{"prepareStatement", VulnSQLInjection},
		{"toInt", VulnSQLInjection},
		{"toInt", VulnCommandInjection},
		{"escapeHtml", VulnXSS},
		{"getName", VulnPathTraversal},
	}
	for _, tt := range tests {
		if !cat.IsSanitizer("scala", tt.call, tt.class) {
			t.Errorf("IsSanitizer(scala, %q, %q) = false, want true", tt.call, tt.class)
		}
	}
	// HTML-escape must NOT defuse SQL injection (class-specific).
	if cat.IsSanitizer("scala", "escapeHtml", VulnSQLInjection) {
		t.Error("escapeHtml must not neutralize sql_injection (class-specific sanitizer)")
	}
}
