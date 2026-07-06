package taint

import "testing"

// TestDefaultLoads verifies the embedded catalog parses and indexes without
// error and is populated for both prioritized languages.
func TestDefaultLoads(t *testing.T) {
	cat, err := Default()
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}
	if cat == nil {
		t.Fatal("Default() returned nil catalog")
	}
	if cat.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", cat.SchemaVersion())
	}
	for _, lang := range []string{"python", "javascript"} {
		if len(cat.Sinks(lang)) == 0 {
			t.Errorf("no sinks loaded for %s", lang)
		}
		if len(cat.Sources(lang)) == 0 {
			t.Errorf("no sources loaded for %s", lang)
		}
		if len(cat.Sanitizers(lang)) == 0 {
			t.Errorf("no sanitizers loaded for %s", lang)
		}
	}
}

// TestDefaultCached verifies the sync.Once caching returns the same instance.
func TestDefaultCached(t *testing.T) {
	a, err := Default()
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}
	b, _ := Default()
	if a != b {
		t.Error("Default() returned different instances; sync.Once caching broken")
	}
}

func TestIsSource(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name string
		lang string
		call string
		want bool
	}{
		{"python http source", "python", "request.args", true},
		{"python env source", "python", "os.getenv", true},
		{"python stdin source", "python", "input", true},
		{"python file source", "python", "open.read", true},
		{"python not a source", "python", "os.system", false},
		{"js http source", "javascript", "req.body", true},
		{"js env source", "javascript", "process.env", true},
		{"ts alias resolves to js", "typescript", "req.query", true},
		{"js alias short form", "js", "req.query", true},
		{"unknown language", "cobol", "params", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cat.IsSource(tt.lang, tt.call); got != tt.want {
				t.Errorf("IsSource(%q, %q) = %v, want %v", tt.lang, tt.call, got, tt.want)
			}
		})
	}
}

func TestIsSink(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name      string
		lang      string
		call      string
		wantOK    bool
		wantClass VulnClass
		wantCWE   string
		wantRule  string
	}{
		{"python os.system", "python", "os.system", true, VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"python cursor.execute", "python", "cursor.execute", true, VulnSQLInjection, "CWE-89", "TAINT-001"},
		{"python eval", "python", "eval", true, VulnCodeInjection, "CWE-95", "TAINT-005"},
		{"python pickle.loads", "python", "pickle.loads", true, VulnUnsafeDeserialization, "CWE-502", "TAINT-005"},
		{"python render_template_string SSTI", "python", "render_template_string", true, VulnSSTI, "CWE-1336", "TAINT-003"},
		{"python requests.get SSRF", "python", "requests.get", true, VulnSSRF, "CWE-918", "TAINT-006"},
		{"python chat completion AI sink", "python", "chat.completions.create", true, VulnPromptInjection, "CWE-77", "TAINT-AI-001"},
		{"js child_process.exec", "javascript", "child_process.exec", true, VulnCommandInjection, "CWE-78", "TAINT-002"},
		{"js Function constructor", "javascript", "Function", true, VulnCodeInjection, "CWE-95", "TAINT-005"},
		{"js innerHTML XSS", "javascript", "element.innerHTML", true, VulnXSS, "CWE-79", "TAINT-003"},
		{"ts alias resolves", "typescript", "eval", true, VulnCodeInjection, "CWE-95", "TAINT-005"},
		{"not a sink", "python", "shlex.quote", false, "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, ok := cat.IsSink(tt.lang, tt.call)
			if ok != tt.wantOK {
				t.Fatalf("IsSink(%q, %q) ok = %v, want %v", tt.lang, tt.call, ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
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

func TestIsSanitizer(t *testing.T) {
	cat := MustDefault()
	tests := []struct {
		name  string
		lang  string
		call  string
		class VulnClass
		want  bool
	}{
		{"shlex.quote defuses cmdi", "python", "shlex.quote", VulnCommandInjection, true},
		{"shlex.quote does not defuse xss", "python", "shlex.quote", VulnXSS, false},
		{"markupsafe.escape defuses xss", "python", "markupsafe.escape", VulnXSS, true},
		{"markupsafe.escape defuses ssti", "python", "markupsafe.escape", VulnSSTI, true},
		{"realpath defuses traversal", "python", "os.path.realpath", VulnPathTraversal, true},
		{"realpath does not defuse cmdi", "python", "os.path.realpath", VulnCommandInjection, false},
		{"yaml.safe_load defuses deser", "python", "yaml.safe_load", VulnUnsafeDeserialization, true},
		{"int defuses sqli", "python", "int", VulnSQLInjection, true},
		{"js DOMPurify defuses xss", "javascript", "DOMPurify.sanitize", VulnXSS, true},
		{"js parseInt defuses cmdi", "javascript", "parseInt", VulnCommandInjection, true},
		{"ts alias resolves", "typescript", "DOMPurify.sanitize", VulnXSS, true},
		{"not a sanitizer", "python", "os.system", VulnCommandInjection, false},
		{"unknown language", "cobol", "escape", VulnXSS, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cat.IsSanitizer(tt.lang, tt.call, tt.class); got != tt.want {
				t.Errorf("IsSanitizer(%q, %q, %q) = %v, want %v", tt.lang, tt.call, tt.class, got, tt.want)
			}
		})
	}
}

// TestSinkInvariants verifies every loaded sink has the fields downstream
// finding emission depends on.
func TestSinkInvariants(t *testing.T) {
	cat := MustDefault()
	for _, lang := range cat.Languages() {
		for _, s := range cat.Sinks(lang) {
			if s.Call == "" {
				t.Errorf("%s: sink with empty call", lang)
			}
			if s.VulnClass == "" {
				t.Errorf("%s: sink %q missing vuln_class", lang, s.Call)
			}
			if s.CWE == "" {
				t.Errorf("%s: sink %q missing CWE", lang, s.Call)
			}
			if s.RuleID == "" {
				t.Errorf("%s: sink %q missing rule_id", lang, s.Call)
			}
		}
	}
}

// TestSanitizerInvariants verifies each sanitizer neutralizes at least one class.
func TestSanitizerInvariants(t *testing.T) {
	cat := MustDefault()
	for _, lang := range cat.Languages() {
		for _, s := range cat.Sanitizers(lang) {
			if len(s.Neutralizes) == 0 {
				t.Errorf("%s: sanitizer %q neutralizes nothing", lang, s.Call)
			}
		}
	}
}
