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

func TestCollectDeclaredSetupCfg(t *testing.T) {
	// httpie's layout: setup.py is `setup()` and every requirement lives in
	// setup.cfg under [options] and [options.extras_require].
	files := map[string][]byte{
		"setup.py": []byte("from setuptools import setup\n\nsetup()\n"),
		"setup.cfg": []byte(`[metadata]
name = httpie

[options]
packages = find:
install_requires =
    pip
    charset_normalizer>=2.0.0
    requests[socks] >=2.22.0
    Pygments>=2.5.2
    importlib-metadata>=1.4.0; python_version<"3.8"
    colorama>=0.2.4; sys_platform=="win32"
python_requires = >=3.7

[options.extras_require]
dev =
    pytest
    pytest-httpbin>=0.0.6
    responses
test = pyyaml

[flake8]
max-line-length = 120
`),
	}
	d := collectDeclared(files)
	for _, imp := range []string{"pip", "charset_normalizer", "requests", "pygments", "importlib_metadata", "colorama", "pytest", "pytest_httpbin", "responses", "yaml"} {
		if !d.hasPyPI(imp) {
			t.Errorf("setup.cfg: import root %q should be declared", imp)
		}
	}
	for _, imp := range []string{"packages", "find", "python_requires", "max_line_length", "flake8"} {
		if d.hasPyPI(imp) {
			t.Errorf("setup.cfg: %q is not a requirement and must not be declared", imp)
		}
	}
}

func TestCollectDeclaredSetupPy(t *testing.T) {
	// certbot's layout: module-level lists passed to setup(), an f-string
	// requirement, and an extras_require dict of lists.
	files := map[string][]byte{
		"setup.py": []byte(`from setuptools import setup

version = "4.0.0"

install_requires = [
    # comment with a bracket ] inside
    f'acme>={version}',
    'ConfigArgParse>=1.5.3',
    "cryptography>=43.0.0",
    'pyopenssl>=25.0.0',
]

extras_require = {
    'docs': ['Sphinx>=1.0', 'sphinx_rtd_theme'],
    'test': ['pytest', 'pytest-xdist'],
}

setup(
    name='certbot',
    install_requires=install_requires,
    extras_require=extras_require,
    tests_require=['coverage'],
)
`),
	}
	d := collectDeclared(files)
	for _, imp := range []string{"acme", "configargparse", "cryptography", "OpenSSL", "sphinx", "sphinx_rtd_theme", "pytest", "pytest_xdist", "coverage"} {
		if !d.hasPyPI(imp) {
			t.Errorf("setup.py: import root %q should be declared", imp)
		}
	}
	for _, imp := range []string{"certbot", "setuptools", "version", "name"} {
		if d.hasPyPI(imp) {
			t.Errorf("setup.py: %q is not a requirement and must not be declared", imp)
		}
	}
}

func TestHasPyPINamespaceRoot(t *testing.T) {
	files := map[string][]byte{
		"requirements.txt": []byte("zope.interface\nbackports.zoneinfo\nruamel.yaml\n"),
	}
	d := collectDeclared(files)
	for _, imp := range []string{"zope", "backports", "ruamel"} {
		if !d.hasPyPI(imp) {
			t.Errorf("namespace root %q should be vouched for by its dotted distribution", imp)
		}
	}
}

func TestHasPyPIMixedCaseImportMapping(t *testing.T) {
	files := map[string][]byte{
		"requirements.txt": []byte("pyOpenSSL\npywin32\ndnspython\n"),
	}
	d := collectDeclared(files)
	for _, imp := range []string{"OpenSSL", "win32security", "pywintypes", "dns"} {
		if !d.hasPyPI(imp) {
			t.Errorf("hasPyPI(%q) should be true through the import-to-dist mapping", imp)
		}
	}
}

func TestHasPyPIConventionalPrefix(t *testing.T) {
	files := map[string][]byte{
		"requirements.txt": []byte("python-digitalocean>=1.15\npython-augeas\npyserial\npy-cpuinfo\n"),
	}
	d := collectDeclared(files)
	for _, imp := range []string{"digitalocean", "augeas", "serial", "cpuinfo"} {
		if !d.hasPyPI(imp) {
			t.Errorf("hasPyPI(%q) should resolve through the python-/py- naming convention", imp)
		}
	}
	if d.hasPyPI("thon") { // "py"+"thon" != "python-digitalocean"; no accidental substring match
		t.Error("prefix convention must be an exact-name check")
	}
}
