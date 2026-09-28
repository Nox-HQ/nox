package hardening

import "testing"

func TestInsecureCookiePython(t *testing.T) {
	for name, c := range map[string]struct {
		src  string
		want int
	}{
		"flask secure=False":   {"resp.set_cookie('sid', v, secure=False, httponly=True)\n", 1},
		"spread over lines":    {"resp.set_cookie(\n    cookie, value,\n    path=request.path,\n    secure=False,\n    httponly=True)\n", 1},
		"django signed cookie": {"response.set_signed_cookie('k', v, salt='s', secure=False)\n", 1},
		"secure=True":          {"resp.set_cookie('sid', v, secure=True)\n", 0},
		"omitted flag":         {"resp.set_cookie('sid', v)\n", 0},
		"config-driven flag":   {"resp.set_cookie('sid', v, secure=not app.debug)\n", 0},
		"a nested call's keyword is not the cookie's": {"resp.set_cookie('sid', make(v, secure=False))\n", 0},
		"commented out":               {"# resp.set_cookie('sid', v, secure=False)\n", 0},
		"inside a string":             {"doc = \"call set_cookie(name, v, secure=False) to...\"\n", 0},
		"unrelated secure=False":      {"client = Client(secure=False)\n", 0},
		"a framework's own signature": {"    def set_cookie(self, key, value, expires=None, secure=False, httponly=False):\n", 0},
		"async handler signature":     {"async def set_cookie(request, samesite='lax', secure=False):\n", 0},
	} {
		got := scanPythonCookies("app.py", []byte(c.src))
		if len(got) != c.want {
			t.Errorf("%s: got %d findings, want %d: %+v", name, len(got), c.want, got)
		}
	}
}

func TestInsecureCookieReportsTheFlagLine(t *testing.T) {
	src := "resp.set_cookie(\n    cookie, value,\n    secure=False)\n"
	got := scanPythonCookies("app.py", []byte(src))
	if len(got) != 1 || got[0].Location.StartLine != 3 {
		t.Fatalf("want one finding on line 3, got %+v", got)
	}
}
