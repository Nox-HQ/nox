package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestFunctionScopeEnds pins that a statement after a function's body belongs
// to the scope around it, not to the function. Six extractors opened a unit at
// each header and never closed it, so top-level code was recorded as the last
// function's (see scopestack.go).
func TestFunctionScopeEnds(t *testing.T) {
	tests := []struct {
		name, path, src string
		// want maps a call to the unit that must hold it.
		want map[string]string
	}{
		{name: "python if-main block", path: "a.py",
			src:  "def helper(b):\n    inner(b)\n\nif __name__ == \"__main__\":\n    topcall(1)\n",
			want: map[string]string{"inner": "helper", "topcall": ""}},
		{name: "python method then module code", path: "a.py",
			src:  "class S:\n    def a(self):\n        ina()\n    def b(self):\n        inb()\n\ntopcall()\n",
			want: map[string]string{"ina": "a", "inb": "b", "topcall": ""}},
		{name: "python nested def returns to its parent", path: "a.py",
			src:  "def outer():\n    def inner():\n        deep()\n    after()\n",
			want: map[string]string{"deep": "inner", "after": "outer"}},
		{name: "python dedented string stays in the function", path: "a.py",
			src:  "def f():\n    q = \"\"\"\nSELECT 1\n\"\"\"\n    run(q)\n",
			want: map[string]string{"run": "f"}},
		{name: "ruby", path: "a.rb",
			src:  "def helper(b)\n  inner(b)\nend\ntopcall(1)\n",
			want: map[string]string{"inner": "helper", "topcall": ""}},
		{name: "lua", path: "a.lua",
			src:  "local function helper(b)\n  inner(b)\nend\ntopcall(1)\n",
			want: map[string]string{"inner": "helper", "topcall": ""}},
		{name: "php", path: "a.php",
			src:  "<?php\nfunction helper($b) {\n    inner($b);\n}\ntopcall(1);\n",
			want: map[string]string{"inner": "helper", "topcall": ""}},
		{name: "php allman brace", path: "a.php",
			src:  "<?php\nfunction helper($b)\n{\n    inner($b);\n}\ntopcall(1);\n",
			want: map[string]string{"inner": "helper", "topcall": ""}},
		{name: "php one-line body", path: "a.php",
			src:  "<?php\nfunction helper($b) { inner($b); }\ntopcall(1);\n",
			want: map[string]string{"inner": "helper", "topcall": ""}},
		{name: "perl", path: "a.pl",
			src:  "sub helper {\n  inner($_[0]);\n}\ntopcall(1);\n",
			want: map[string]string{"inner": "helper", "topcall": ""}},
		{name: "perl one-line body", path: "a.pl",
			// A body on the header line is not read by the Perl extractor at
			// all; what this pins is that the scope still closes after it.
			src:  "sub helper { inner($_[0]); }\ntopcall(1);\n",
			want: map[string]string{"topcall": ""}},
		{name: "powershell", path: "a.ps1",
			src:  "function helper($b) {\n  inner $b\n}\ntopcall 1\n",
			want: map[string]string{"inner": "helper", "topcall": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			units := ExtractUnits(tt.path, lexctx.LangFromPath(tt.path), []byte(tt.src))
			for call, wantUnit := range tt.want {
				var holders []string
				for _, u := range units {
					for _, s := range u.Stmts {
						if slices.Contains(s.Calls, call) {
							holders = append(holders, u.FuncName)
						}
					}
				}
				if len(holders) != 1 || holders[0] != wantUnit {
					t.Errorf("%s() is held by units %q, want only %q", call, holders, wantUnit)
				}
			}
		})
	}
}
