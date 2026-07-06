package taint

import "testing"

// TestKotlinCatalogSinks asserts the Kotlin language block carries the sinks the
// precision suite annotations require, with the exact rule_id/cwe/vuln_class the
// tp_*.kt samples expect.
func TestKotlinCatalogSinks(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name      string
		call      string
		wantClass VulnClass
		wantCWE   string
		wantRule  string
	}{
		{"exec cmdi", "exec", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"ProcessBuilder cmdi", "ProcessBuilder", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"executeQuery sqli", "executeQuery", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"execute sqli", "execute", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"rawQuery sqli", "rawQuery", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"File path", "File", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"FileInputStream path", "FileInputStream", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"readText path", "readText", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"openStream ssrf", "openStream", VulnSSRF, "CWE-918", "TAINT-006"},
		{"openConnection ssrf", "openConnection", VulnSSRF, "CWE-918", "TAINT-006"},
		{"readObject deser", "ObjectInputStream.readObject", VulnUnsafeDeserialization, "CWE-502", "TAINT-005"},
		{"write xss", "write", VulnXSS, "CWE-79", "TAINT-003"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, ok := cat.IsSink("kotlin", tt.call)
			if !ok {
				t.Fatalf("IsSink(kotlin, %q) = false, want true", tt.call)
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

// TestKotlinCatalogSources asserts the untrusted-input sources are present,
// including the Android intent extras.
func TestKotlinCatalogSources(t *testing.T) {
	cat := MustDefault()
	for _, call := range []string{
		"request.getParameter", "request.getHeader", "request.getQueryString",
		"intent.getStringExtra", "intent.getData",
	} {
		if !cat.IsSource("kotlin", call) {
			t.Errorf("IsSource(kotlin, %q) = false, want true", call)
		}
	}
}

// TestKotlinCatalogSanitizers asserts each sanitizer neutralizes exactly the
// class(es) its sink family needs: prepareStatement defuses SQLi, HTML encoders
// defuse XSS, numeric coercion defuses the injection families, and File(...).name
// defuses path traversal.
func TestKotlinCatalogSanitizers(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		call  string
		class VulnClass
	}{
		{"prepareStatement", VulnSQLInjection},
		{"toInt", VulnSQLInjection},
		{"toIntOrNull", VulnCommandInjection},
		{"toLong", VulnPathTraversal},
		{"escapeHtml4", VulnXSS},
		{"htmlEscape", VulnXSS},
		{"name", VulnPathTraversal},
	}
	for _, tt := range tests {
		if !cat.IsSanitizer("kotlin", tt.call, tt.class) {
			t.Errorf("IsSanitizer(kotlin, %q, %q) = false, want true", tt.call, tt.class)
		}
	}
	// An HTML encoder must NOT defuse SQL injection (class-specific).
	if cat.IsSanitizer("kotlin", "escapeHtml4", VulnSQLInjection) {
		t.Error("escapeHtml4 must not neutralize sql_injection (class-specific sanitizer)")
	}
	// Numeric coercion must NOT defuse XSS.
	if cat.IsSanitizer("kotlin", "toInt", VulnXSS) {
		t.Error("toInt must not neutralize xss (class-specific sanitizer)")
	}
}
