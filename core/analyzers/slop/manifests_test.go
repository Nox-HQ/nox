package slop

import "testing"

func TestNormalizePyPI(t *testing.T) {
	cases := map[string]string{
		"Flask_Login": "flask-login",
		"flask-login": "flask-login",
		"Flask.Login": "flask-login",
		"PyYAML":      "pyyaml",
		"a--b":        "a-b",
	}
	for in, want := range cases {
		if got := normalizePyPI(in); got != want {
			t.Errorf("normalizePyPI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCollectDeclaredNPM(t *testing.T) {
	files := map[string][]byte{
		"package.json": []byte(`{
			"name": "myapp",
			"dependencies": {"express": "^4", "@scope/pkg": "1.0.0"},
			"devDependencies": {"@types/node": "20", "vitest": "1"}
		}`),
	}
	d := collectDeclared(files)
	for _, name := range []string{"express", "@scope/pkg", "vitest", "@types/node", "node", "myapp"} {
		if !d.hasNPM(name) {
			t.Errorf("expected npm declared: %q", name)
		}
	}
	if d.hasNPM("left-pad") {
		t.Error("left-pad should not be declared")
	}
}

func TestCollectDeclaredPyPI(t *testing.T) {
	files := map[string][]byte{
		"requirements.txt": []byte("Flask>=2.0\nrequests==2.31.0\n# comment\n-r other.txt\npyyaml\n"),
		"pyproject.toml":   []byte("[project]\ndependencies = [\"httpx>=0.27\", \"pydantic\"]\n"),
		"Pipfile":          []byte("[packages]\nboto3 = \"*\"\n"),
	}
	d := collectDeclared(files)
	for _, imp := range []string{"flask", "requests", "yaml", "httpx", "pydantic", "boto3"} {
		if !d.hasPyPI(imp) {
			t.Errorf("expected pypi declared for import root %q", imp)
		}
	}
	if d.hasPyPI("torch") {
		t.Error("torch should not be declared")
	}
}

func TestHasPyPIImportMapping(t *testing.T) {
	files := map[string][]byte{
		"requirements.txt": []byte("opencv-python\nscikit-learn\nbeautifulsoup4\n"),
	}
	d := collectDeclared(files)
	// Import roots differ from distribution names — the mapping must bridge them.
	for imp, ok := range map[string]bool{"cv2": true, "sklearn": true, "bs4": true, "cv3": false} {
		if d.hasPyPI(imp) != ok {
			t.Errorf("hasPyPI(%q) = %v, want %v", imp, d.hasPyPI(imp), ok)
		}
	}
}
