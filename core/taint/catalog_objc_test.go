package taint

import "testing"

// TestObjCCatalogSinks asserts the Objective-C language block carries the sinks
// the precision suite annotations require, keyed on the message-send selector
// suffix the extractor produces (`[recv selector:arg]` -> `recv.selector`), with
// the exact rule_id/cwe/vuln_class the tp_*.m samples expect.
func TestObjCCatalogSinks(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name      string
		call      string
		wantClass VulnClass
		wantCWE   string
		wantRule  string
	}{
		{"system cmdi", "system", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"popen cmdi", "popen", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"execl cmdi", "execl", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"NSTask launch cmdi", "launch", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"sqlite3_exec sqli", "sqlite3_exec", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"executeQuery sqli", "executeQuery", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"fopen path", "fopen", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"contentsOfFile path", "stringWithContentsOfFile", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"dataWithContentsOfFile path", "dataWithContentsOfFile", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"dataTaskWithURL ssrf", "dataTaskWithURL", VulnSSRF, "CWE-918", "TAINT-006"},
		{"sendSynchronousRequest ssrf", "sendSynchronousRequest", VulnSSRF, "CWE-918", "TAINT-006"},
		{"unarchiveObjectWithData deser", "unarchiveObjectWithData", VulnUnsafeDeserialization, "CWE-502", "TAINT-005"},
		{"loadHTMLString xss", "loadHTMLString", VulnXSS, "CWE-79", "TAINT-003"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, ok := cat.IsSink("objc", tt.call)
			if !ok {
				t.Fatalf("IsSink(objc, %q) = false, want true", tt.call)
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

// TestObjCCatalogSources asserts the untrusted-input sources are present, keyed
// on the bare selector/attribute suffix.
func TestObjCCatalogSources(t *testing.T) {
	cat := MustDefault()
	for _, call := range []string{
		"getenv", "NSProcessInfo.environment", "text", "objectForKey",
	} {
		if !cat.IsSource("objc", call) {
			t.Errorf("IsSource(objc, %q) = false, want true", call)
		}
	}
}

// TestObjCCatalogSanitizers asserts each sanitizer neutralizes exactly the
// class(es) its sink family needs: sqlite3_bind defuses SQLi, intValue coercion
// defuses the injection families, lastPathComponent defuses path traversal, and
// HTML-escape defuses XSS — never crossing classes.
func TestObjCCatalogSanitizers(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		call  string
		class VulnClass
	}{
		{"sqlite3_bind_text", VulnSQLInjection},
		{"sqlite3_bind", VulnSQLInjection},
		{"intValue", VulnSQLInjection},
		{"integerValue", VulnPathTraversal},
		{"lastPathComponent", VulnPathTraversal},
		{"stringByAddingPercentEncodingWithAllowedCharacters", VulnSSRF},
		{"escapeHTML", VulnXSS},
	}
	for _, tt := range tests {
		if !cat.IsSanitizer("objc", tt.call, tt.class) {
			t.Errorf("IsSanitizer(objc, %q, %q) = false, want true", tt.call, tt.class)
		}
	}
	// A class-specific sanitizer must NOT cross classes.
	if cat.IsSanitizer("objc", "escapeHTML", VulnSQLInjection) {
		t.Error("escapeHTML must not neutralize sql_injection (class-specific sanitizer)")
	}
	if cat.IsSanitizer("objc", "lastPathComponent", VulnSSRF) {
		t.Error("lastPathComponent must not neutralize ssrf (class-specific sanitizer)")
	}
}
