package depimports

import "testing"

func pyUse(t *testing.T, file, src, module, name string) bool {
	t.Helper()
	ix := New()
	ix.Add(file, []byte(src))
	_, ok := ix.PySymbolUse(module, name)
	return ok
}

// Every ordinary way of importing and using a function or class of a module
// must be seen.
func TestPySymbolUseOrdinaryIdioms(t *testing.T) {
	cases := []struct{ name, file, src, module, sym string }{
		{"from import", "app.py", "from PIL.Image import open\nimg = open(p)\n", "PIL.Image", "open"},
		{"from import alias", "app.py", "from PIL.Image import open as load\nload(p)\n", "PIL.Image", "open"},
		{"from import list", "app.py", "from jwt.api_jwt import encode, decode\ndecode(t)\n", "jwt.api_jwt", "decode"},
		{"from import parenthesised", "app.py", "from jwt.api_jwt import (\n    encode,\n    decode as d,\n)\nd(t)\n", "jwt.api_jwt", "decode"},
		{"submodule from parent", "app.py", "from PIL import Image\nImage.open(p)\n", "PIL.Image", "open"},
		{"import module", "app.py", "import yaml\nyaml.load(s)\n", "yaml", "load"},
		{"import dotted", "app.py", "import PIL.Image\nPIL.Image.open(p)\n", "PIL.Image", "open"},
		{"import alias", "app.py", "import numpy.lib.format as fmt\nfmt.read_array(f)\n", "numpy.lib.format", "read_array"},
		{"attribute chain from top", "app.py", "import requests\nrequests.sessions.Session()\n", "requests.sessions", "Session"},
		{"class used", "app.py", "from rest_framework.parsers import JSONParser\nparser_classes = [JSONParser]\n", "rest_framework.parsers", "JSONParser"},
		{"import inside function", "app.py", "def f():\n    import yaml\n    return yaml.load(s)\n", "yaml", "load"},
		{"import list", "app.py", "import os, yaml\nyaml.load(s)\n", "yaml", "load"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !pyUse(t, c.file, c.src, c.module, c.sym) {
				t.Errorf("no use of %s.%s found in %q", c.module, c.sym, c.src)
			}
		})
	}
}

// A use that is not one must not be reported.
func TestPySymbolUseNegatives(t *testing.T) {
	cases := []struct{ name, file, src, module, sym string }{
		{"imported, never used", "app.py", "from PIL.Image import open\n", "PIL.Image", "open"},
		{"other module's name", "app.py", "import yaml\nother.load(s)\n", "yaml", "load"},
		{"same name, another object", "app.py", "from yaml import load\nx.load(s)\n", "yaml", "load"},
		{"in a comment", "app.py", "import yaml\n# yaml.load(s)\n", "yaml", "load"},
		{"in a string", "app.py", "import yaml\nmsg = 'yaml.load(s)'\n", "yaml", "load"},
		{"test file", "tests/test_app.py", "import yaml\nyaml.load(s)\n", "yaml", "load"},
		{"test prefix", "pkg/test_load.py", "import yaml\nyaml.load(s)\n", "yaml", "load"},
		{"conftest", "conftest.py", "import yaml\nyaml.load(s)\n", "yaml", "load"},
		{"relative import", "app.py", "from .yaml import load\nload(s)\n", "yaml", "load"},
		{"wrong module", "app.py", "from PIL.ImageFile import open\nopen(p)\n", "PIL.Image", "open"},
		{"star import", "app.py", "from yaml import *\nload(s)\n", "yaml", "load"},
		{"prefix of a name", "app.py", "import yaml\nyaml.load_all(s)\n", "yaml", "load"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if pyUse(t, c.file, c.src, c.module, c.sym) {
				t.Errorf("reported a use of %s.%s in %q", c.module, c.sym, c.src)
			}
		})
	}
}

// The witness is the first use in path order, so it does not depend on the
// order files are read in.
func TestPySymbolUseWitnessIsDeterministic(t *testing.T) {
	a := []byte("import yaml\n\nyaml.load(s)\n")
	b := []byte("import yaml\nyaml.load(s)\n")
	for _, order := range [][2]string{{"b.py", "a.py"}, {"a.py", "b.py"}} {
		ix := New()
		for _, f := range order {
			if f == "a.py" {
				ix.Add(f, a)
			} else {
				ix.Add(f, b)
			}
		}
		u, ok := ix.PySymbolUse("yaml", "load")
		if !ok || u.File != "a.py" || u.Line != 3 {
			t.Errorf("order %v: witness %+v ok=%v, want a.py:3", order, u, ok)
		}
	}
}
