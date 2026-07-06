package taint

import "testing"

// TestClojureCatalogSinks asserts the Clojure language block carries the sinks the
// precision suite annotations require, with the exact rule_id/cwe/vuln_class the
// tp_*.clj samples expect (TAINT-001, TAINT-002, TAINT-004, TAINT-005, TAINT-006).
func TestClojureCatalogSinks(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name      string
		call      string
		wantClass VulnClass
		wantCWE   string
		wantRule  string
	}{
		{"shell/sh cmdi", "shell/sh", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"clojure.java.shell/sh cmdi", "clojure.java.shell/sh", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{".exec cmdi", ".exec", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"eval code", "eval", VulnCodeInjection, "CWE-95", "TAINT-005"},
		{"load-string code", "load-string", VulnCodeInjection, "CWE-95", "TAINT-005"},
		{"jdbc/query sqli", "jdbc/query", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"slurp path", "slurp", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"io/reader path", "io/reader", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"client/get ssrf", "client/get", VulnSSRF, "CWE-918", "TAINT-006"},
		{"clj-http.client/get ssrf", "clj-http.client/get", VulnSSRF, "CWE-918", "TAINT-006"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, ok := cat.IsSink("clojure", tt.call)
			if !ok {
				t.Fatalf("IsSink(clojure, %q) = false, want true", tt.call)
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

// TestClojureCatalogSources asserts the untrusted-input sources are present: the
// Ring request keyword-access (with and without the leading colon, since the
// extractor strips it), the JVM environment, and the command-line args.
func TestClojureCatalogSources(t *testing.T) {
	cat := MustDefault()
	for _, call := range []string{
		":params", "params", ":query-string", "query-string",
		"System/getenv", "*command-line-args*", "read-line",
	} {
		if !cat.IsSource("clojure", call) {
			t.Errorf("IsSource(clojure, %q) = false, want true", call)
		}
	}
}

// TestClojureCatalogSanitizers asserts Integer/parseInt and parse-long coerce a
// value to a number, neutralizing the injection families, and that no sanitizer
// crosses into an unrelated class it does not claim.
func TestClojureCatalogSanitizers(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		call  string
		class VulnClass
	}{
		{"Integer/parseInt", VulnCommandInjection},
		{"Integer/parseInt", VulnSQLInjection},
		{"Integer/parseInt", VulnCodeInjection},
		{"Integer/parseInt", VulnPathTraversal},
		{"parse-long", VulnCommandInjection},
	}
	for _, tt := range tests {
		if !cat.IsSanitizer("clojure", tt.call, tt.class) {
			t.Errorf("IsSanitizer(clojure, %q, %q) = false, want true", tt.call, tt.class)
		}
	}
	// Integer/parseInt is a value-coercion sanitizer; it does NOT claim SSRF (a
	// numeric coercion does not stop a request from reaching an attacker host).
	if cat.IsSanitizer("clojure", "Integer/parseInt", VulnSSRF) {
		t.Error("Integer/parseInt must not neutralize ssrf")
	}
}
