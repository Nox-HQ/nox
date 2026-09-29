package weakcrypto

import (
	"strings"
	"testing"
)

// TestPythonFlagsSecurityUseOfRandom covers what the rule is for in Python: a
// `random` draw the surrounding code names as security-bearing. Each case
// asserts the name the finding blames, so a case passing for the wrong reason
// fails.
func TestPythonFlagsSecurityUseOfRandom(t *testing.T) {
	for _, c := range []struct{ name, src, wantCtx string }{
		{
			name:    "assignment to a security-named variable",
			src:     "import random\ndef f():\n    token = random.getrandbits(128)\n    return token\n",
			wantCtx: "token",
		},
		{
			name:    "the classic weak token generator: choices joined into a string",
			src:     "import random, string\ndef make():\n    reset_token = ''.join(random.choice(string.ascii_letters) for _ in range(32))\n    return reset_token\n",
			wantCtx: "reset_token",
		},
		{
			name:    "a join spread over several lines is one statement",
			src:     "import random\ndef make():\n    api_key = ''.join(\n        random.choice(ALPHABET)\n        for _ in range(40)\n    )\n    return api_key\n",
			wantCtx: "api_key",
		},
		{
			name:    "aliased module",
			src:     "import random as rnd\ndef f():\n    csrf = str(rnd.random())\n    return csrf\n",
			wantCtx: "csrf",
		},
		{
			name:    "from-import of the function",
			src:     "from random import randint\ndef f():\n    otp = randint(100000, 999999)\n    return otp\n",
			wantCtx: "otp",
		},
		{
			name:    "a random.Random instance draws the same way",
			src:     "import random\nrng = random.Random()\ndef f():\n    nonce = rng.getrandbits(64)\n    return nonce\n",
			wantCtx: "nonce",
		},
		{
			name:    "keyword argument",
			src:     "import random\ndef f(resp):\n    resp.set_cookie('sid', session_id=random.random())\n",
			wantCtx: "session_id",
		},
		{
			name:    "dict key",
			src:     "import random\ndef f():\n    return {'password': str(random.randint(0, 10**8))}\n",
			wantCtx: "password",
		},
		{
			name:    "subscript store with a string key",
			src:     "import random\ndef f(session):\n    session['token'] = random.random()\n",
			wantCtx: "session",
		},
		{
			name: "one forward hop: a neutral name stored into a session",
			src: "import random\ndef handler():\n    value = str(random.getrandbits(32))\n" +
				"    mysession[cookie] = value\n    return value\n",
			wantCtx: "my_session",
		},
		{
			name:    "augmented assignment",
			src:     "import random, string\ndef f():\n    key = ''\n    key += ''.join(random.choice(string.digits) for _ in range(4))\n    return key\n",
			wantCtx: "key",
		},
		{
			name:    "producer function",
			src:     "import random\ndef generate_password():\n    return str(random.random())\n",
			wantCtx: "generate_password",
		},
		{
			name: "code-kind words inside a handler name do not veto",
			src: "import random\ndef BenchmarkTest00025_post():\n    value = str(random.normalvariate())[2:]\n" +
				"    mysession[cookie] = value\n",
			wantCtx: "my_session",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := scanGo(t, "app.py", c.src)
			if len(got) != 1 {
				t.Fatalf("want 1 CRYPTO-002 finding, got %d: %+v", len(got), got)
			}
			if ctx := got[0].Metadata["context"]; ctx != c.wantCtx {
				t.Fatalf("finding blames %q, want %q", ctx, c.wantCtx)
			}
			if !strings.HasPrefix(got[0].Metadata["function"], "random.") {
				t.Fatalf("function metadata %q", got[0].Metadata["function"])
			}
		})
	}
}

// TestPythonIgnoresBenignOrSafeRandomness is the other half: the uses the rule
// exists NOT to report. Each would be noise, and noise is how a rule is
// disabled.
func TestPythonIgnoresBenignOrSafeRandomness(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"secrets is the fix", "import secrets\ndef f():\n    token = secrets.token_urlsafe(32)\n"},
		{"SystemRandom is the OS CSPRNG", "import random\ndef f():\n    token = random.SystemRandom().randint(0, 2**32)\n"},
		{"SystemRandom instance", "import random\nsr = random.SystemRandom()\ndef f():\n    token = sr.getrandbits(64)\n"},
		{"neutral name, neutral use", "import random\ndef f():\n    x = random.random()\n    return x * 2\n"},
		{"jitter vetoes", "import random\ndef refresh_token():\n    delay = random.uniform(0, 1)\n    time.sleep(delay)\n"},
		{"retry vetoes even beside a security word", "import random\ndef f():\n    token_retry_delay = random.random()\n"},
		{"choosing an element is not making a secret", "import random\ndef f(keys):\n    key = random.choice(keys)\n    return key\n"},
		{"len-bounded draw is an index", "import random\ndef f(tokens):\n    token = tokens[random.randint(0, len(tokens) - 1)]\n"},
		{"a pytest test is vetoed by name", "import random\ndef test_session():\n    session_key = random.random()\n"},
		{"monkey is not a key", "import random\ndef f():\n    monkey = random.random()\n"},
		{"no import of random", "def f():\n    token = random.random()\n"},
		{"comment is not code", "import random\ndef f():\n    # token = random.random()\n    pass\n"},
		{"string is not code", "import random\ndef f():\n    doc = 'token = random.random()'\n"},
		{"module level has no scope to follow a neutral name through", "import random\nvalue = random.random()\nsession['x'] = value\n"},
		{"forward hop stops at reassignment", "import random\ndef f():\n    value = random.random()\n    value = secrets.token_hex()\n    session['x'] = value\n"},
		{"forward hop skips a getter's argument", "import random\ndef main():\n    udp = random.random() * 1000\n    csrf_token = get_csrf_token(udp)\n"},
		{"a guess is not a secret", "import random\ndef crack(chars, password):\n    guess_password = random.choices(chars, k=len(password))\n"},
		{"lookup exonerates", "import random\ndef f(cache):\n    return cache.get_token(random.randint(0, 9))\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := scanGo(t, "app.py", c.src); len(got) != 0 {
				t.Fatalf("want no finding, got %+v", got)
			}
		})
	}
}

func TestPythonRandSkipsTestFiles(t *testing.T) {
	src := "import random\ndef f():\n    token = random.random()\n"
	if got := scanGo(t, "tests/test_auth.py", src); len(got) != 0 {
		t.Fatalf("test file reported: %+v", got)
	}
}

func TestPythonFindingLineIsTheCall(t *testing.T) {
	src := "import random\n\ndef make():\n    api_key = ''.join(\n        random.choice(A)\n        for _ in range(40))\n"
	got := scanGo(t, "app.py", src)
	if len(got) != 1 || got[0].Location.StartLine != 5 {
		t.Fatalf("want one finding on line 5, got %+v", got)
	}
}

func TestUnglue(t *testing.T) {
	for in, want := range map[string]string{
		"mysession": "my_session",
		"authtoken": "auth_token",
		"monkey":    "monkey",
		"hotkey":    "hotkey",
		"session":   "session",
		"userToken": "user_token",
	} {
		if got := unglue(in); got != want {
			t.Errorf("unglue(%q) = %q, want %q", in, got, want)
		}
	}
}
