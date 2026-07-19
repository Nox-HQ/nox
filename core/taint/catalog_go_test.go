package taint

import "testing"

// TestGoCatalogSinks asserts the Go language block carries the sinks the precision
// corpus annotations require, with the exact rule_id/cwe/vuln_class the six tp_*.go
// samples expect.
func TestGoCatalogSinks(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name      string
		call      string
		wantClass VulnClass
		wantCWE   string
		wantRule  string
	}{
		{"exec.Command cmdi", "exec.Command", VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"db.Query sqli", "db.Query", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"db.Exec sqli", "db.Exec", VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"os.ReadFile path", "os.ReadFile", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"os.Open path", "os.Open", VulnPathTraversal, "CWE-22", "TAINT-004"},
		{"http.Get ssrf", "http.Get", VulnSSRF, "CWE-918", "TAINT-006"},
		{"gob.NewDecoder deser", "gob.NewDecoder", VulnUnsafeDeserialization, "CWE-502", "TAINT-005"},
		{"yaml.Unmarshal deser", "yaml.Unmarshal", VulnUnsafeDeserialization, "CWE-502", "TAINT-005"},
		{"template.New.Parse ssti", "template.New.Parse", VulnSSTI, "CWE-1336", "TAINT-003"},
		// XSS-to-response sinks (tier-2): tainted data written as HTML to an
		// http.ResponseWriter is reflected XSS — TAINT-003, xss, CWE-79.
		{"fmt.Fprintf xss", "fmt.Fprintf", VulnXSS, "CWE-79", "TAINT-003"},
		{"fmt.Fprint xss", "fmt.Fprint", VulnXSS, "CWE-79", "TAINT-003"},
		{"fmt.Fprintln xss", "fmt.Fprintln", VulnXSS, "CWE-79", "TAINT-003"},
		{"w.Write xss", "w.Write", VulnXSS, "CWE-79", "TAINT-003"},
		{"io.WriteString xss", "io.WriteString", VulnXSS, "CWE-79", "TAINT-003"},
		{"template.HTML autoescape bypass", "template.HTML", VulnXSS, "CWE-79", "TAINT-003"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, ok := cat.IsSink("go", tt.call)
			if !ok {
				t.Fatalf("IsSink(go, %q) = false, want true", tt.call)
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

// TestGoCatalogSources asserts the untrusted-input sources are present and that
// os.Getenv is deliberately NOT a source (it would create FPs on the clean
// placeholder sample).
func TestGoCatalogSources(t *testing.T) {
	cat := MustDefault()
	for _, call := range []string{"URL.Query.Get", "r.FormValue", "r.Header.Get", "r.Body", "os.Args"} {
		if !cat.IsSource("go", call) {
			t.Errorf("IsSource(go, %q) = false, want true", call)
		}
	}
	if cat.IsSource("go", "os.Getenv") {
		t.Errorf("os.Getenv must NOT be a Go source (protects clean_placeholders.go precision)")
	}
}

// TestGoCatalogSanitizers asserts the neutralizers and their classes.
func TestGoCatalogSanitizers(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		call  string
		class VulnClass
	}{
		{"filepath.Clean", VulnPathTraversal},
		{"filepath.Base", VulnPathTraversal},
		{"url.QueryEscape", VulnSSRF},
		{"strconv.Atoi", VulnCommandInjection},
		{"strconv.Atoi", VulnSQLInjection},
	}
	for _, tt := range tests {
		if !cat.IsSanitizer("go", tt.call, tt.class) {
			t.Errorf("IsSanitizer(go, %q, %q) = false, want true", tt.call, tt.class)
		}
	}
}

// Open redirect (TAINT-007, CWE-601) was folded in from nox-plugin-sast's
// SAST-008 when that plugin was retired. In the catalogue it is taint-gated:
// the plugin matched `res.redirect(...req.query)` textually, whereas a sink
// only fires when untrusted input actually reaches it — so a redirect to a
// constant path is correctly silent.
func TestCatalog_OpenRedirectSink(t *testing.T) {
	c := MustDefault()
	s, ok := c.IsSink("go", "http.Redirect")
	if !ok {
		t.Fatal("http.Redirect should be an open-redirect sink")
	}
	if s.VulnClass != VulnOpenRedirect {
		t.Errorf("vuln class = %q, want %q", s.VulnClass, VulnOpenRedirect)
	}
	if s.CWE != "CWE-601" {
		t.Errorf("cwe = %q, want CWE-601", s.CWE)
	}
	if s.RuleID != "TAINT-007" {
		t.Errorf("rule id = %q, want TAINT-007", s.RuleID)
	}
}

func TestCatalog_OpenRedirectAcrossLanguages(t *testing.T) {
	c := MustDefault()
	for _, tc := range []struct{ lang, call string }{
		{"python", "redirect"},
		{"python", "HttpResponseRedirect"},
		{"javascript", "res.redirect"},
		{"java", "sendRedirect"},
		{"ruby", "redirect_to"},
	} {
		s, ok := c.IsSink(tc.lang, tc.call)
		if !ok {
			t.Errorf("%s/%s should be a sink", tc.lang, tc.call)
			continue
		}
		if s.VulnClass != VulnOpenRedirect {
			t.Errorf("%s/%s class = %q, want %q", tc.lang, tc.call, s.VulnClass, VulnOpenRedirect)
		}
	}
}
