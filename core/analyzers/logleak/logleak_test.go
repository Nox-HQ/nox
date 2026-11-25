package logleak

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/lexctx"
)

type tc struct {
	name, src string
	want      []int
}

func run(t *testing.T, path string, lang lexctx.Lang, cases []tc) {
	t.Helper()
	for _, c := range cases {
		var got []int
		for _, f := range ScanFile(path, lang, []byte(c.src)) {
			got = append(got, f.Location.StartLine)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: lines %v, want %v", c.name, got, c.want)
		}
	}
}

func TestJavaScript(t *testing.T) {
	run(t, "server/src/routes/auth.ts", lexctx.LangJavaScript, []tc{
		{"a reset token", "console.log(`Password reset token for ${email}: ${resetToken}`);\n", []int{1}},
		{"a password argument", "logger.info('created user', email, password);\n", []int{1}},
		{"the request body", "app.post('/x', (req, res) => {\n  console.error('payout issue', { vendorId: v.id, ...req.body });\n});\n", []int{2}},
		{"the body through an alias", "app.post('/x', (req, res) => {\n  const body = req.body;\n  activityLog.error(`save failed: ${JSON.stringify(body)}`);\n});\n", []int{3}},
		{"the Authorization header", "this.logger.warn(`rejected: ${req.headers.authorization}`);\n", []int{1}},
		{"a NestJS sign-in body", "@Post('login')\nlogin(@Body() loginDto: LoginDto) {\n  this.logger.warn(`Rejected sign-in attempt: ${JSON.stringify(loginDto)}`);\n}\n", []int{3}},
		{"a login form passed along", "async signIn(loginDto: LoginDto) {\n  this.logger.warn(`Rejected: ${JSON.stringify(loginDto)}`);\n}\n", []int{2}},
		{"a token read by a getter", "log.debug('issued', tokens.getToken());\n", []int{1}},
		{"a token made by a call", "log.debug('issued', generateToken(user));\n", []int{1}},
		{"Fastify request log", "req.log.warn({ submission: req.body }, 'failed validation');\n", []int{1}},
		// Not reported.
		{"the word in the message only", "console.log('token refreshed for user', userId);\n", nil},
		{"a name about the token", "logger.info('issued', { tokenType, tokenExpiresAt, tokenId });\n", nil},
		{"the length of the secret", "console.log('secret length', secret.length);\n", nil},
		{"a test of the token", "console.log('has token', token != null, !token);\n", nil},
		{"a masked token", "logger.info('token', mask(token));\n", nil},
		{"a computation on the token", "logger.info('expired', isExpired(token));\n", nil},
		{"one field of the body", "console.log('signup for', req.body.email);\n", nil},
		{"the service, not the secret", "logger.info('verify', tokenService.verify);\n", nil},
		{"a call that checks a token", "logger.info('verified', tokens.verifyToken());\n", nil},
		{"an object key named token", "logger.info('done', { token: 'redacted' });\n", nil},
		{"a body parameter that is not a credential form", "@Post()\ncreate(@Body() brand: BrandDto) {\n  this.logger.debug(`created ${JSON.stringify(brand)}`);\n}\n", nil},
		{"the alias out of scope", "function a(req) {\n  const body = req.body;\n}\nfunction b(body) {\n  console.log(body);\n}\n", nil},
	})
}

func TestBrowserFilesSkipped(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"web/src/components/Editor.ts": "console.log('word', token);\n",
		"web/src/api/session.ts":       "import axios from 'axios';\nconsole.log('session', token);\n",
		"server/src/session.ts":        "import express from 'express';\nimport axios from 'axios';\nconsole.log('session', token);\n",
		"server/src/pages/api/x.ts":    "console.log('session', token);\n",
		// A Next.js server action imports next/navigation for redirect().
		"src/actions/auth.ts": "'use server';\nimport { redirect } from 'next/navigation';\nconsole.log(`reset token: ${token}`);\n",
		"src/lib/nav.ts":      "import { useRouter } from 'next/navigation';\nconsole.log('session', token);\n",
	}
	var arts []discovery.Artifact
	for p, src := range files {
		abs := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		arts = append(arts, discovery.Artifact{Path: p, AbsPath: abs})
	}
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fs.Findings() {
		got = append(got, f.Location.FilePath)
	}
	slices.Sort(got)
	if want := []string{"server/src/pages/api/x.ts", "server/src/session.ts", "src/actions/auth.ts"}; !slices.Equal(got, want) {
		t.Errorf("findings in %v, want %v", got, want)
	}
}

func TestPython(t *testing.T) {
	run(t, "app/views.py", lexctx.LangPython, []tc{
		{"a password in an f-string", "L.info(f\"POST request with username {username} and password {password}\")\n", []int{1}},
		{"the raw body and the Authorization header", "def tally(request):\n    body = request.body.decode('utf-8')\n    logger.warning('body=%s bearer=%s', body, request.headers.get('authorization'))\n", []int{3}},
		{"the decoded body through an alias", "def tally(request):\n    body = request.body.decode('utf-8')\n    logger.warning('body=%s', body)\n", []int{3}},
		{"the awaited body through an alias", "async def tally(request):\n    wire = (await request.body()).decode()\n    logger.warning('intake %s', wire)\n", []int{3}},
		{"a credential read by key", "print(request.form['password'])\n", []int{1}},
		{"Python 2 print statement", "print \"BODY \", self.request.body\n", []int{1}},
		{"an API key", "print('Received key:', api_key)\n", []int{1}},
		{"a value through format", "print('cracked! user: {} password: {}'.format(username, password))\n", []int{1}},
		// Not reported.
		{"a keyword argument name", "logger.info('reset sent', password_reset_requested=True)\n", nil},
		{"the length", "logger.info('len %d', len(password))\n", nil},
		{"a None test", "logger.info('token set: %s', token is not None)\n", nil},
		{"a hashed password", "logger.info('hash %s', hash_password(password))\n", nil},
		{"one field of the body alias", "def a(request):\n    data = request.json\n    logger.info('signup %s', data['email'])\n", nil},
		{"one field of the form", "logger.info('signup %s', request.form.get('email'))\n", nil},
		{"the alias in another function", "def a(request):\n    body = request.body\n\ndef b(body):\n    logger.info(body)\n", nil},
	})
}

func TestDjangoMailBackend(t *testing.T) {
	const line = "EMAIL_BACKEND = \"django.core.mail.backends.console.EmailBackend\"\n"
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"production settings", "portal/settings.py", "DEBUG = False\n" + line, 1},
		{"file backend", "portal/settings/base.py", "EMAIL_BACKEND = 'django.core.mail.backends.filebased.EmailBackend'\n", 1},
		{"env default", "portal/settings.py", "EMAIL_BACKEND = os.getenv(\"EMAIL_BACKEND\", \"django.core.mail.backends.console.EmailBackend\")\n", 1},
		{"development settings", "portal/settings/dev.py", line, 0},
		{"local settings", "portal/settings_local.py", line, 0},
		{"under if DEBUG", "portal/settings.py", "if DEBUG:\n    " + line, 0},
		{"commented out", "portal/settings.py", "# " + line, 0},
		{"inside a docstring", "portal/settings.py", "NOTES = \"\"\"\n" + line + "\"\"\"\n", 0},
		{"SMTP backend", "portal/settings.py", "EMAIL_BACKEND = \"django.core.mail.backends.smtp.EmailBackend\"\n", 0},
		{"not a settings module", "portal/mail.py", line, 0},
	}
	for _, c := range cases {
		if got := len(ScanFile(c.path, lexctx.LangPython, []byte(c.src))); got != c.want {
			t.Errorf("%s: %d findings, want %d", c.name, got, c.want)
		}
	}
}

func TestSQLiteTrace(t *testing.T) {
	run(t, "app/db.py", lexctx.LangPython, []tc{
		{"traced to print", "conn = sqlite3.connect(DB)\nconn.set_trace_callback(print)\n", []int{2}},
		{"traced to a logger", "conn.set_trace_callback(logger.debug)\n", []int{1}},
		{"trace switched off", "conn.set_trace_callback(None)\n", nil},
	})
}

func TestJava(t *testing.T) {
	run(t, "src/main/java/app/AuthService.java", lexctx.LangJava, []tc{
		{"a bearer token", "class A { void a() { log.debug(\"invalid token: {}\", bearerToken); } }\n", []int{1}},
		{"a cookie's value", "class A { void a() {\n  log.debug(\"Cookie value: \" + theCookie.getValue());\n} }\n", []int{2}},
		{"a secret by getter", "class A { void a() { System.out.println(\"key: \" + keyPair.getPrivateKey()); } }\n", []int{1}},
		{"the Authorization header", "class A { void a() { log.info(\"auth {}\", request.getHeader(\"Authorization\")); } }\n", []int{1}},
		{"a Spring sign-in body", "class A {\n  void login(@RequestBody LoginRequest req) {\n    log.warn(\"login failed {}\", req);\n  }\n}\n", []int{3}},
		{"a record accessor", "class A { void a() { log.info(\"posting for account {}\", request.accountNumber()); } }\n", []int{1}},
		{"an account number", "class A { void a() { log.debug(\"Account Number - \" + accountNumber); } }\n", []int{1}},
		// Not reported.
		{"a Spring body that is not a credential form", "class A {\n  void create(@RequestBody BrandParam brand) {\n    log.debug(\"created {}\", brand);\n  }\n}\n", nil},
		{"the token's lifetime", "class A { void a() { log.debug(\"Token life = \" + tokenLife); } }\n", nil},
		{"a computed result", "class A { void a() { System.out.println(!isTokenExpired(token)); } }\n", nil},
		{"the secret's directory", "class A { void a() { log.error(\"cannot write in {}\", secretDirectory); } }\n", nil},
		{"the user's id", "class A { void a() { log.warn(\"reset with mismatched token \" + customer.getId()); } }\n", nil},
	})
}

func TestWords(t *testing.T) {
	cases := map[string][]string{
		"apiKey": {"api", "key"}, "API_KEY": {"api", "key"}, "JWTToken": {"jwt", "token"},
		"passwordResetRequested": {"password", "reset", "requested"}, "$secret": {"secret"},
	}
	for in, want := range cases {
		if got := words(in); !slices.Equal(got, want) {
			t.Errorf("words(%q) = %v, want %v", in, got, want)
		}
	}
}
