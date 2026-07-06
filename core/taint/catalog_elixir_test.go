package taint

import "testing"

// TestElixirCatalogSinks asserts the Elixir language block carries the sinks the
// precision suite annotations require, with the exact rule_id/cwe/vuln_class the
// tp_*.exs samples expect. Note: `:os.cmd`, `:httpc.request`, and
// `:erlang.binary_to_term` are keyed WITHOUT the leading atom colon because the
// extractor normalizes `:mod.fun` to `mod.fun` before catalog lookup.
func TestElixirCatalogSinks(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name      string
		call      string
		wantClass VulnClass
		wantCWE   string
		wantRule  string
	}{
		{"System.cmd cmdi", "System.cmd", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"os.cmd cmdi", "os.cmd", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"Port.open cmdi", "Port.open", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"Code.eval_string code", "Code.eval_string", VulnCodeInjection, "CWE-95", "TAINT-005"},
		{"Code.eval_quoted code", "Code.eval_quoted", VulnCodeInjection, "CWE-95", "TAINT-005"},
		{"erlang.binary_to_term deser", "erlang.binary_to_term", VulnUnsafeDeserialization, "CWE-502", "TAINT-005"},
		{"Repo.query sqli", "Repo.query", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"fragment sqli", "fragment", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"File.read path", "File.read", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"File.open path", "File.open", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"File.stream path (bang normalized)", "File.stream", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"HTTPoison.get ssrf", "HTTPoison.get", VulnSSRF, "CWE-918", "TAINT-006"},
		{"httpc.request ssrf", "httpc.request", VulnSSRF, "CWE-918", "TAINT-006"},
		{"Finch.build ssrf", "Finch.build", VulnSSRF, "CWE-918", "TAINT-006"},
		{"Req.get ssrf", "Req.get", VulnSSRF, "CWE-918", "TAINT-006"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, ok := cat.IsSink("elixir", tt.call)
			if !ok {
				t.Fatalf("IsSink(elixir, %q) = false, want true", tt.call)
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

// TestElixirCatalogSources asserts the untrusted-input sources are present.
func TestElixirCatalogSources(t *testing.T) {
	cat := MustDefault()
	for _, call := range []string{
		"conn.params", "conn.query_params", "conn.body_params",
		"System.get_env", "System.argv", "IO.read",
	} {
		if !cat.IsSource("elixir", call) {
			t.Errorf("IsSource(elixir, %q) = false, want true", call)
		}
	}
}

// TestElixirCatalogSanitizers asserts each sanitizer neutralizes the class(es)
// its family needs: String.to_integer coercion defuses the injection families,
// Path.basename defuses path traversal — never crossing into unrelated classes.
func TestElixirCatalogSanitizers(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		call  string
		class VulnClass
	}{
		{"String.to_integer", VulnSQLInjection},
		{"String.to_integer", VulnCommandInjection},
		{"String.to_integer", VulnPathTraversal},
		{"Path.basename", VulnPathTraversal},
		{"Path.expand", VulnPathTraversal},
	}
	for _, tt := range tests {
		if !cat.IsSanitizer("elixir", tt.call, tt.class) {
			t.Errorf("IsSanitizer(elixir, %q, %q) = false, want true", tt.call, tt.class)
		}
	}
	// A class-specific sanitizer must NOT cross classes.
	if cat.IsSanitizer("elixir", "Path.basename", VulnSSRF) {
		t.Error("Path.basename must not neutralize ssrf (class-specific sanitizer)")
	}
	if cat.IsSanitizer("elixir", "Path.basename", VulnSQLInjection) {
		t.Error("Path.basename must not neutralize sql_injection (class-specific sanitizer)")
	}
}
