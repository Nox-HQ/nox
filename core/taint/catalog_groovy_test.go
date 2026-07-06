package taint

import "testing"

// TestGroovyCatalogSinks asserts the Groovy language block carries the sinks the
// precision suite annotations require, with the exact rule_id/cwe/vuln_class the
// tp_*.groovy samples expect. Groovy's idioms differ from Java: command execution
// is the String receiver method "cmd".execute() (keyed on the .execute suffix) and
// Jenkins sh/bat steps; SQL is groovy.sql.Sql (rows/executeQuery); code eval is
// Eval.me / GroovyShell.evaluate.
func TestGroovyCatalogSinks(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name      string
		call      string
		wantClass VulnClass
		wantCWE   string
		wantRule  string
	}{
		{"String.execute cmdi", "execute", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"Runtime.exec cmdi", "exec", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"ProcessBuilder cmdi", "ProcessBuilder", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"Jenkins sh cmdi", "sh", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"Jenkins bat cmdi", "bat", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"Eval.me codei", "Eval.me", VulnCodeInjection, "CWE-95", "TAINT-005"},
		{"evaluate codei", "evaluate", VulnCodeInjection, "CWE-95", "TAINT-005"},
		{"GroovyShell.evaluate codei", "GroovyShell.evaluate", VulnCodeInjection, "CWE-95", "TAINT-005"},
		{"Sql.rows sqli", "rows", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"executeQuery sqli", "executeQuery", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"firstRow sqli", "firstRow", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"File path", "File", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"readLines path", "readLines", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"getText path", "getText", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"openStream ssrf", "openStream", VulnSSRF, "CWE-918", "TAINT-006"},
		{"toURL ssrf", "toURL", VulnSSRF, "CWE-918", "TAINT-006"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, ok := cat.IsSink("groovy", tt.call)
			if !ok {
				t.Fatalf("IsSink(groovy, %q) = false, want true", tt.call)
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

// TestGroovyCatalogSources asserts the untrusted-input sources are present,
// including the Jenkins pipeline `params` and top-level script `args`.
func TestGroovyCatalogSources(t *testing.T) {
	cat := MustDefault()
	for _, call := range []string{
		"params", "request.getParameter", "System.getenv", "args",
	} {
		if !cat.IsSource("groovy", call) {
			t.Errorf("IsSource(groovy, %q) = false, want true", call)
		}
	}
}

// TestGroovyCatalogSanitizers asserts each sanitizer neutralizes exactly the
// class(es) its sink family needs: numeric coercion defuses the injection
// families, HTML encoders defuse XSS (only), FilenameUtils.getName defuses path
// traversal.
func TestGroovyCatalogSanitizers(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		call  string
		class VulnClass
	}{
		{"toInteger", VulnSQLInjection},
		{"toInteger", VulnCommandInjection},
		{"Integer.parseInt", VulnCodeInjection},
		{"escapeHtml4", VulnXSS},
		{"encodeAsHTML", VulnXSS},
		{"getName", VulnPathTraversal},
	}
	for _, tt := range tests {
		if !cat.IsSanitizer("groovy", tt.call, tt.class) {
			t.Errorf("IsSanitizer(groovy, %q, %q) = false, want true", tt.call, tt.class)
		}
	}
	// An HTML encoder must NOT defuse SQL injection (class-specific).
	if cat.IsSanitizer("groovy", "escapeHtml4", VulnSQLInjection) {
		t.Error("escapeHtml4 must not neutralize sql_injection (class-specific sanitizer)")
	}
	// Numeric coercion must NOT defuse XSS.
	if cat.IsSanitizer("groovy", "toInteger", VulnXSS) {
		t.Error("toInteger must not neutralize xss (class-specific sanitizer)")
	}
}
