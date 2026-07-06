package taint

import "testing"

// TestSwiftCatalogSinks asserts the Swift language block carries the sinks the
// precision suite annotations require, with the exact rule_id/cwe/vuln_class the
// tp_*.swift samples expect.
func TestSwiftCatalogSinks(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name      string
		call      string
		wantClass VulnClass
		wantCWE   string
		wantRule  string
	}{
		{"Process.launch cmdi", "Process.launch", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"system cmdi", "system", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"sqlite3_exec sqli", "sqlite3_exec", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"String.contentsOfFile path", "String.contentsOfFile", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"Data.contentsOf path", "Data.contentsOf", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"dataTask.with ssrf", "dataTask.with", VulnSSRF, "CWE-918", "TAINT-006"},
		{"unarchiveObject.with deser", "unarchiveObject.with", VulnUnsafeDeserialization, "CWE-502", "TAINT-005"},
		{"loadHTMLString xss", "loadHTMLString", VulnXSS, "CWE-79", "TAINT-003"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, ok := cat.IsSink("swift", tt.call)
			if !ok {
				t.Fatalf("IsSink(swift, %q) = false, want true", tt.call)
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

// TestSwiftCatalogSources asserts the untrusted-input sources are present.
func TestSwiftCatalogSources(t *testing.T) {
	cat := MustDefault()
	for _, call := range []string{
		"CommandLine.arguments", "ProcessInfo.processInfo.environment",
		"URLComponents.queryItems", "req.query", "req.parameters", "textField.text",
	} {
		if !cat.IsSource("swift", call) {
			t.Errorf("IsSource(swift, %q) = false, want true", call)
		}
	}
}

// TestSwiftCatalogSanitizers asserts each sanitizer neutralizes exactly the
// class(es) its sink family needs: sqlite bind defuses SQLi, Int() coercion
// defuses the injection families, lastPathComponent defuses path traversal, and
// HTML-escape defuses XSS — never crossing classes.
func TestSwiftCatalogSanitizers(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		call  string
		class VulnClass
	}{
		{"sqlite3_bind_text", VulnSQLInjection},
		{"sqlite3_bind", VulnSQLInjection},
		{"bind", VulnSQLInjection},
		{"Int", VulnSQLInjection},
		{"Int", VulnPathTraversal},
		{"lastPathComponent", VulnPathTraversal},
		{"escapeHTML", VulnXSS},
	}
	for _, tt := range tests {
		if !cat.IsSanitizer("swift", tt.call, tt.class) {
			t.Errorf("IsSanitizer(swift, %q, %q) = false, want true", tt.call, tt.class)
		}
	}
	// A class-specific sanitizer must NOT cross classes.
	if cat.IsSanitizer("swift", "escapeHTML", VulnSQLInjection) {
		t.Error("escapeHTML must not neutralize sql_injection (class-specific sanitizer)")
	}
	if cat.IsSanitizer("swift", "lastPathComponent", VulnSSRF) {
		t.Error("lastPathComponent must not neutralize ssrf (class-specific sanitizer)")
	}
}
