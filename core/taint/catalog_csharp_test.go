package taint

import "testing"

// TestCSharpCatalogSinks asserts the C# language block carries the sinks the
// precision suite annotations require, with the exact rule_id/cwe/vuln_class the
// tp_*.cs samples expect.
func TestCSharpCatalogSinks(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name      string
		call      string
		wantClass VulnClass
		wantCWE   string
		wantRule  string
	}{
		{"Process.Start cmdi", "Process.Start", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"SqlCommand sqli", "SqlCommand", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"ExecuteReader sqli", "ExecuteReader", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"ExecuteNonQuery sqli", "ExecuteNonQuery", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"File.ReadAllText path", "File.ReadAllText", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"StreamReader path", "StreamReader", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"WebClient.DownloadString ssrf", "WebClient.DownloadString", VulnSSRF, "CWE-918", "TAINT-006"},
		{"WebRequest.Create ssrf", "WebRequest.Create", VulnSSRF, "CWE-918", "TAINT-006"},
		{"BinaryFormatter.Deserialize deser", "BinaryFormatter.Deserialize", VulnUnsafeDeserialization, "CWE-502", "TAINT-005"},
		{"Response.Write xss", "Response.Write", VulnXSS, "CWE-79", "TAINT-003"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, ok := cat.IsSink("csharp", tt.call)
			if !ok {
				t.Fatalf("IsSink(csharp, %q) = false, want true", tt.call)
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

// TestCSharpCatalogSources asserts the untrusted-input sources are present.
func TestCSharpCatalogSources(t *testing.T) {
	cat := MustDefault()
	for _, call := range []string{
		"Request.QueryString", "Request.Form", "Request.Params",
		"Request.Headers", "Request.Cookies", "Console.ReadLine",
	} {
		if !cat.IsSource("csharp", call) {
			t.Errorf("IsSource(csharp, %q) = false, want true", call)
		}
	}
}

// TestCSharpCatalogSanitizers asserts each sanitizer neutralizes exactly the
// class(es) its sink family needs: parameterization defuses SQLi, HtmlEncode
// defuses XSS, and numeric coercion defuses the injection families.
func TestCSharpCatalogSanitizers(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		call  string
		class VulnClass
	}{
		{"SqlParameter", VulnSQLInjection},
		{"Parameters.Add", VulnSQLInjection},
		{"HttpUtility.HtmlEncode", VulnXSS},
		{"WebUtility.HtmlEncode", VulnXSS},
		{"int.Parse", VulnSQLInjection},
		{"int.TryParse", VulnCommandInjection},
		{"Path.GetFileName", VulnPathTraversal},
	}
	for _, tt := range tests {
		if !cat.IsSanitizer("csharp", tt.call, tt.class) {
			t.Errorf("IsSanitizer(csharp, %q, %q) = false, want true", tt.call, tt.class)
		}
	}
	// HtmlEncode must NOT defuse SQL injection (class-specific).
	if cat.IsSanitizer("csharp", "HttpUtility.HtmlEncode", VulnSQLInjection) {
		t.Error("HtmlEncode must not neutralize sql_injection (class-specific sanitizer)")
	}
}
