package taint

import "testing"

// TestDartCatalogSinks asserts the Dart language block carries the sinks the
// precision suite annotations require, with the exact rule_id/cwe/vuln_class the
// tp_*.dart samples expect.
func TestDartCatalogSinks(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name      string
		call      string
		wantClass VulnClass
		wantCWE   string
		wantRule  string
	}{
		{"Process.run cmdi", "Process.run", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"Process.start cmdi", "Process.start", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"rawQuery sqli", "rawQuery", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"rawInsert sqli", "rawInsert", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"execute sqli", "execute", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"readAsString path", "readAsString", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"readAsBytes path", "readAsBytes", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"HttpClient.getUrl ssrf", "HttpClient.getUrl", VulnSSRF, "CWE-918", "TAINT-006"},
		{"http.get ssrf", "http.get", VulnSSRF, "CWE-918", "TAINT-006"},
		{"Dio.get ssrf", "Dio.get", VulnSSRF, "CWE-918", "TAINT-006"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, ok := cat.IsSink("dart", tt.call)
			if !ok {
				t.Fatalf("IsSink(dart, %q) = false, want true", tt.call)
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

// TestDartCatalogSources asserts the untrusted-input sources are present.
func TestDartCatalogSources(t *testing.T) {
	cat := MustDefault()
	for _, call := range []string{
		"Platform.environment", "args",
		"request.uri.queryParameters", "request.requestedUri", "stdin",
	} {
		if !cat.IsSource("dart", call) {
			t.Errorf("IsSource(dart, %q) = false, want true", call)
		}
	}
}

// TestDartCatalogSanitizers asserts each sanitizer neutralizes exactly the
// class(es) its sink family needs: a bind/placeholder defuses SQLi, int.parse
// coercion defuses the injection families, and HTML-escape defuses XSS — never
// crossing classes.
func TestDartCatalogSanitizers(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		call  string
		class VulnClass
	}{
		{"int.parse", VulnSQLInjection},
		{"int.parse", VulnCommandInjection},
		{"int.parse", VulnPathTraversal},
		{"htmlEscape", VulnXSS},
	}
	for _, tt := range tests {
		if !cat.IsSanitizer("dart", tt.call, tt.class) {
			t.Errorf("IsSanitizer(dart, %q, %q) = false, want true", tt.call, tt.class)
		}
	}
	// A class-specific sanitizer must NOT cross classes.
	if cat.IsSanitizer("dart", "htmlEscape", VulnSQLInjection) {
		t.Error("htmlEscape must not neutralize sql_injection (class-specific sanitizer)")
	}
}
