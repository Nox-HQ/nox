package taint

import "testing"

// TestLuaCatalogSinks asserts the Lua language block carries the sinks the
// precision suite annotations require, with the exact rule_id/cwe/vuln_class the
// tp_*.lua samples expect.
func TestLuaCatalogSinks(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name      string
		call      string
		wantClass VulnClass
		wantCWE   string
		wantRule  string
	}{
		{"os.execute cmdi", "os.execute", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"io.popen cmdi", "io.popen", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"loadstring code", "loadstring", VulnCodeInjection, "CWE-95", "TAINT-005"},
		{"load code", "load", VulnCodeInjection, "CWE-95", "TAINT-005"},
		{"loadfile code", "loadfile", VulnCodeInjection, "CWE-95", "TAINT-005"},
		{"dofile code", "dofile", VulnCodeInjection, "CWE-95", "TAINT-005"},
		{"io.open path", "io.open", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"db.exec sqli", "db.exec", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"conn.execute sqli", "conn.execute", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"http.request ssrf", "http.request", VulnSSRF, "CWE-918", "TAINT-006"},
		{"httpc.request_uri ssrf", "httpc.request_uri", VulnSSRF, "CWE-918", "TAINT-006"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, ok := cat.IsSink("lua", tt.call)
			if !ok {
				t.Fatalf("IsSink(lua, %q) = false, want true", tt.call)
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

// TestLuaCatalogSources asserts the untrusted-input sources are present.
func TestLuaCatalogSources(t *testing.T) {
	cat := MustDefault()
	for _, call := range []string{
		"arg", "os.getenv", "io.read", "ngx.var",
		"ngx.req.get_uri_args", "ngx.req.get_post_args",
	} {
		if !cat.IsSource("lua", call) {
			t.Errorf("IsSource(lua, %q) = false, want true", call)
		}
	}
}

// TestLuaCatalogSanitizers asserts each sanitizer neutralizes the class(es) its
// sink family needs — tonumber coerces to a number and defuses every injection
// family, and the SQL-escape helpers defuse only SQLi — never crossing classes.
func TestLuaCatalogSanitizers(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		call  string
		class VulnClass
	}{
		{"tonumber", VulnCommandInjection},
		{"tonumber", VulnCodeInjection},
		{"tonumber", VulnPathTraversal},
		{"tonumber", VulnSQLInjection},
		{"tonumber", VulnSSRF},
		{"ngx.quote_sql_str", VulnSQLInjection},
		{"escape", VulnSQLInjection},
	}
	for _, tt := range tests {
		if !cat.IsSanitizer("lua", tt.call, tt.class) {
			t.Errorf("IsSanitizer(lua, %q, %q) = false, want true", tt.call, tt.class)
		}
	}
	// A class-specific SQL sanitizer must NOT cross classes.
	if cat.IsSanitizer("lua", "ngx.quote_sql_str", VulnCommandInjection) {
		t.Error("ngx.quote_sql_str must not neutralize command_injection (class-specific sanitizer)")
	}
}
