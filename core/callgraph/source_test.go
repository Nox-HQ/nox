package callgraph

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/taint/engine"
)

// buildSource extracts each file's units the way the scan does and builds the
// graph.
func buildSource(t *testing.T, files map[string]string, routes []Route) *Graph {
	t.Helper()
	b := NewSourceBuilder()
	for p, src := range files {
		units := engine.ExtractUnits(p, lexctx.LangFromPath(p), []byte(src))
		b.Add(p, []byte(src), units)
	}
	return b.Build(routes)
}

func TestSourcePathFromEntry(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]string
		routes    []Route
		target    string
		wantPath  []string
		wantEntry EntryKind
	}{
		{
			name: "python: if-main block through a helper module",
			files: map[string]string{
				"app.py":     "from helpers import run_cmd\n\ndef run(x):\n    run_cmd(x)\n\nif __name__ == \"__main__\":\n    run(1)\n",
				"helpers.py": "import os\n\ndef run_cmd(c):\n    os.system(c)\n",
			},
			target:    "helpers.py:run_cmd",
			wantPath:  []string{"app.py:<module>", "app.py:run", "helpers.py:run_cmd"},
			wantEntry: EntryConcrete,
		},
		{
			name: "javascript: an inline route callback is an entry a request reaches",
			files: map[string]string{
				"app.js": "const express = require('express');\nconst app = express();\n\nfunction helper(x) {\n  exec(x);\n}\n\napp.get('/x', (req, res) => {\n  helper(req.query.a);\n});\n",
			},
			routes:    []Route{{Method: "GET", Path: "/x", File: "app.js", Line: 8, Reader: "Express or Fastify"}},
			target:    "app.js:helper",
			wantPath:  []string{"app.js:<anonymous>@8", "app.js:helper"},
			wantEntry: EntryRoute,
		},
		{
			name: "javascript: a handler the registration names",
			files: map[string]string{
				"app.js": "const app = require('express')();\n\nfunction save(b) {\n  db.write(b);\n}\n\nfunction create(req, res) {\n  save(req.body);\n}\n\napp.post('/y', create);\n",
			},
			routes:    []Route{{Method: "POST", Path: "/y", File: "app.js", Line: 11, Reader: "Express or Fastify"}},
			target:    "app.js:save",
			wantPath:  []string{"app.js:create", "app.js:save"},
			wantEntry: EntryRoute,
		},
		{
			name: "javascript: a relative import",
			files: map[string]string{
				"src/main.js":     "import { parse } from './lib/util';\nparse(process.argv[2]);\n",
				"src/lib/util.js": "export function parse(s) {\n  return JSON.parse(s);\n}\n",
			},
			target:    "src/lib/util.js:parse",
			wantPath:  []string{"src/main.js:<module>", "src/lib/util.js:parse"},
			wantEntry: EntryConcrete,
		},
		{
			name: "python: a decorated route handler",
			files: map[string]string{
				"web.py": "from flask import Flask\napp = Flask(__name__)\n\ndef load(i):\n    return db.get(i)\n\n@app.route('/item/<i>')\ndef item(i):\n    return load(i)\n",
			},
			routes:    []Route{{Method: "GET", Path: "/item/<i>", File: "web.py", Line: 7, Reader: "Flask"}},
			target:    "web.py:load",
			wantPath:  []string{"web.py:item", "web.py:load"},
			wantEntry: EntryRoute,
		},
		{
			name: "java: main, a same-class call and a call through the class name",
			files: map[string]string{
				"App.java":   "public class App {\n  public static void main(String[] args) {\n    new App().run(args[0]);\n  }\n\n  void run(String a) {\n    Util.clean(a);\n  }\n}\n",
				"Util.java":  "public class Util {\n  static String clean(String s) {\n    return s.trim();\n  }\n}\n",
				"Other.java": "public class Other {\n  void unrelated() {\n    System.out.println(1);\n  }\n}\n",
			},
			target:    "Util.java:clean",
			wantPath:  []string{"App.java:main", "App.java:run", "Util.java:clean"},
			wantEntry: EntryConcrete,
		},
		{
			name: "a test file's call is a test entry, not a concrete one",
			files: map[string]string{
				"lib.py":            "def f(x):\n    return x\n",
				"tests/test_lib.py": "from lib import f\n\ndef test_f():\n    f(1)\n",
			},
			target:    "lib.py:f",
			wantPath:  []string{"tests/test_lib.py:test_f", "lib.py:f"},
			wantEntry: EntryTest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := buildSource(t, tt.files, tt.routes)
			if _, ok := g.Func(tt.target); !ok {
				t.Fatalf("no function %q; have %v", tt.target, keysOf(g))
			}
			path, kind := g.PathToFunc(tt.target)
			if !reflect.DeepEqual(path, tt.wantPath) || kind != tt.wantEntry {
				t.Errorf("PathToFunc(%s) = %v from %s, want %v from %s", tt.target, path, kind, tt.wantPath, tt.wantEntry)
			}
		})
	}
}

// The counterexamples: each is a call a looser resolver would bind, and a
// witness built on it would be false.
func TestSourceDoesNotGuess(t *testing.T) {
	t.Run("a bare name defined in two files binds to neither", func(t *testing.T) {
		g := buildSource(t, map[string]string{
			"main.py": "helper(1)\n",
			"a.py":    "def helper(x):\n    return x\n",
			"b.py":    "def helper(x):\n    return x\n",
		}, nil)
		for _, k := range []string{"a.py:helper", "b.py:helper"} {
			if p, _ := g.PathToFunc(k); len(p) > 1 {
				t.Errorf("%s reached through %v; the call names two functions", k, p)
			}
		}
	})
	t.Run("a method on a value of unknown type is not bound by name", func(t *testing.T) {
		g := buildSource(t, map[string]string{
			"app.py": "def json(x):\n    return x\n\nr = fetch()\nr.json()\n",
		}, nil)
		if p, _ := g.PathToFunc("app.py:json"); len(p) > 1 {
			t.Errorf("r.json() bound to the local json: %v", p)
		}
	})
	t.Run("an imported name is the import's, not a local function's", func(t *testing.T) {
		g := buildSource(t, map[string]string{
			"app.py":   "from jinja2 import Template\nTemplate(\"x\")\n",
			"local.py": "def Template(s):\n    return s\n",
		}, nil)
		if p, _ := g.PathToFunc("local.py:Template"); len(p) > 1 {
			t.Errorf("an imported Template bound to local.py: %v", p)
		}
		if got := g.CallersOfDependency("PyPI", "jinja2"); !reflect.DeepEqual(got, []string{"app.py:<module>"}) {
			t.Errorf("CallersOfDependency(jinja2) = %v", got)
		}
	})
	t.Run("a route registration does not adopt an unrelated function below it", func(t *testing.T) {
		g := buildSource(t, map[string]string{
			"app.js": "app.post('/y', create);\n\nfunction create(req, res) {\n  ok();\n}\n",
		}, []Route{{Method: "POST", Path: "/y", File: "app.js", Line: 1}})
		f, _ := g.Func("app.js:create")
		if f.Kind != EntryRoute {
			t.Fatalf("create is %s, want route (it is the named handler)", f.Kind)
		}
	})
}

func TestSourceDependencyCallers(t *testing.T) {
	g := buildSource(t, map[string]string{
		"a.py":         "import requests as rq\n\ndef fetch(u):\n    return rq.get(u)\n",
		"b.py":         "def other(yaml):\n    return yaml.load(1)\n",
		"c.js":         "import ax from 'axios';\nexport function f(u) {\n  return ax.get(u);\n}\n",
		"d.rb":         "require 'nokogiri'\n\ndef parse(x)\n  Nokogiri::XML(x)\nend\n",
		"e.js":         "const lodash = 1;\nfunction g() {\n  lodash.template('x');\n}\n",
		"s3.ts":        "import { S3Client } from '@aws-sdk/client-s3';\nexport function mk() {\n  return new S3Client({});\n}\n",
		"chart.js":     "import Chart from 'chart.js';\nfunction draw() {\n  Chart.register();\n}\n",
		"yaml_user.py": "import yaml\n\ndef load(s):\n    return yaml.safe_load(s)\n",
	}, nil)
	tests := []struct {
		eco, name string
		want      []string
	}{
		{"PyPI", "requests", []string{"a.py:fetch"}},
		// b.py calls yaml.load on a parameter named yaml and imports nothing.
		{"PyPI", "pyyaml", nil},
		{"PyPI", "yaml", []string{"yaml_user.py:load"}},
		{"npm", "axios", []string{"c.js:f"}},
		{"RubyGems", "nokogiri", []string{"d.rb:parse"}},
		// e.js has a local named lodash and no import of it.
		{"npm", "lodash", nil},
		{"npm", "@aws-sdk/client-s3", []string{"s3.ts:mk"}},
		{"npm", "chart.js", []string{"chart.js:draw"}},
	}
	for _, tt := range tests {
		got := g.CallersOfDependency(tt.eco, tt.name)
		if len(got) == 0 && len(tt.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("CallersOfDependency(%s, %s) = %v, want %v", tt.eco, tt.name, got, tt.want)
		}
	}
}

func TestSourceFuncAtModuleCodeAfterAFunction(t *testing.T) {
	g := buildSource(t, map[string]string{
		"a.py": "def helper(b):\n    inner(b)\n\nsink(input())\n",
	}, nil)
	if k, ok := g.FuncAt("a.py", 2); !ok || k != "a.py:helper" {
		t.Errorf("FuncAt(a.py:2) = %q, %v, want a.py:helper", k, ok)
	}
	if k, ok := g.FuncAt("a.py", 4); !ok || k != "a.py:<module>" {
		t.Errorf("FuncAt(a.py:4) = %q, %v, want a.py:<module>", k, ok)
	}
	if !strings.Contains(g.Scope().Analysis, "source") {
		t.Errorf("scope analysis = %q", g.Scope().Analysis)
	}
	if len(g.Scope().Limitations) == 0 {
		t.Error("a syntactic graph must carry a limitation, or reach.Refute would trust it")
	}
}

func keysOf(g *Graph) []string {
	var out []string
	for k := range g.funcs {
		out = append(out, k)
	}
	return out
}

// A finding on the middle line of a multi-line statement belongs to that
// statement's function; a line after the next function's header does not.
func TestSourceFuncAtContinuationLines(t *testing.T) {
	g := buildSource(t, map[string]string{
		"a.js": "function send(u) {\n  post(u, {\n    token: 'x',\n    url: u,\n  });\n}\nfunction next() {\n  const k = 1;\n}\n",
	}, nil)
	for line, want := range map[int]string{3: "a.js:send", 4: "a.js:send"} {
		if k, ok := g.FuncAt("a.js", line); !ok || k != want {
			t.Errorf("FuncAt(a.js:%d) = %q, %v, want %s", line, k, ok, want)
		}
	}
	if k, ok := g.FuncAt("a.js", 7); ok {
		t.Errorf("FuncAt(a.js:7), the next function's header, = %q", k)
	}
}
