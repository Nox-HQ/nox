package authz

import (
	"fmt"
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// throttleFindings returns "RULE route" for every AUTHN-002 and AUTHN-003
// finding.
func throttleFindings(fs []findings.Finding) []string {
	var out []string
	for _, f := range fs {
		if f.RuleID == BruteForceRuleID || f.RuleID == UnthrottledIssueRuleID {
			out = append(out, f.RuleID+" "+f.Metadata["route"])
		}
	}
	slices.Sort(out)
	return out
}

const bcryptLogin = "async (req, res) => { const u = await db.user(req.body.email); if (!u || !(await bcrypt.compare(req.body.password, u.hash))) return res.status(401).end(); res.json({ token: sign(u) }); }"

func TestUnthrottledCredentialRoutes(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		// What the claims report.
		{"express login", express("app.post('/api/auth/login', " + bcryptLogin + ");\n"),
			[]string{"AUTHN-002 POST /api/auth/login"}},
		{"login named by its path, inline 401 does not authenticate it", express("app.post('/login', (req, res) => res.status(401).end());\n"),
			[]string{"AUTHN-002 POST /login"}},
		{"reset consumed by token", express("app.post('/reset-password/:token', (req, res) => res.end());\n"),
			[]string{"AUTHN-002 POST /reset-password/:token"}},
		{"otp verification", express("app.post('/auth/otp/verify', (req, res) => res.end());\n"),
			[]string{"AUTHN-002 POST /auth/otp/verify"}},
		{"password check named only by its handler", express("app.post('/kiosk/checkin', " + bcryptLogin + ");\n"),
			[]string{"AUTHN-002 POST /kiosk/checkin"}},
		{"registration", express("app.post('/api/auth/register', (req, res) => res.end());\n"),
			[]string{"AUTHN-003 POST /api/auth/register"}},
		{"forgot password", express("app.post('/forgot-password', (req, res) => res.end());\n"),
			[]string{"AUTHN-003 POST /forgot-password"}},
		{"otp issued, not checked", express("app.post('/auth/otp/request', (req, res) => res.end());\n"),
			[]string{"AUTHN-003 POST /auth/otp/request"}},
		{"flask login", map[string]string{"app.py": "from flask import Flask, request\napp = Flask(__name__)\n@app.route('/login', methods=['POST'])\ndef login():\n    return 'x'\n"},
			[]string{"AUTHN-002 POST /login"}},
		{"spring form login", map[string]string{"src/main/java/app/Sec.java": "package app;\nclass Sec {\n  SecurityFilterChain c(HttpSecurity http) throws Exception {\n    return http.formLogin(f -> f.loginPage(\"/login\")).build();\n  }\n}\n"},
			[]string{"AUTHN-002 Spring Security form login"}},
		{"spring http basic", map[string]string{"src/main/java/app/Sec.java": "package app;\nclass Sec {\n  SecurityFilterChain c(HttpSecurity http) throws Exception {\n    return http.httpBasic(Customizer.withDefaults()).build();\n  }\n}\n"},
			[]string{"AUTHN-002 Spring Security HTTP Basic"}},

		{"nest: the service's password check is not read into every route", map[string]string{
			"src/auth.controller.ts": nestHead + "@Controller('auth')\nexport class AuthController {\n  constructor(private readonly auth: AuthService) {}\n  @Post('login')\n  login(@Body() dto: LoginDto) { return this.auth.login(dto); }\n  @Post('preferences')\n  prefs(@Body() dto: PrefsDto) { return this.auth.prefs(dto); }\n}\n",
			"src/auth.service.ts":    "import { Injectable } from '@nestjs/common';\n@Injectable()\nexport class AuthService {\n  async login(dto) { return bcrypt.compare(dto.password, 'h'); }\n  async prefs(dto) { return dto; }\n}\n"},
			[]string{"AUTHN-002 POST /auth/login"}},

		// Counterexamples: each removes the claim.
		{"limiter on the route", express("const loginLimiter = makeLimiter();\napp.post('/login', loginLimiter, " + bcryptLogin + ");\n"), nil},
		{"flask limiter decorator", map[string]string{"app.py": "from flask import Flask\nfrom flask_limiter import Limiter\napp = Flask(__name__)\nlimiter = Limiter(app)\n@app.route('/login', methods=['POST'])\n@limiter.limit('5/minute')\ndef login():\n    return 'x'\n"}, nil},
		{"limiter on the application", express("app.use(rateLimit({ windowMs: 60000, max: 100 }));\napp.post('/login', " + bcryptLogin + ");\n"), nil},
		{"fastify rate limit registered globally", map[string]string{"server.js": "const fastify = require('fastify')();\nfastify.register(require('@fastify/rate-limit'), { max: 100 });\nfastify.post('/login', async (req) => ({}));\n"}, nil},
		{"lockout in the handler", express("app.post('/login', async (req, res) => { if (user.failedAttempts >= 5) return res.status(423).end(); res.end(); });\n"), nil},
		{"authentication middleware", express("app.post('/account/password', requireAuth, " + bcryptLogin + ");\n"), nil},
		{"inline principal on a route not named for login", express("app.post('/account/password', async (req, res) => { const u = req.user; if (!(await bcrypt.compare(req.body.current, u.hash))) return res.status(401).end(); res.end(); });\n"), nil},
		{"GET login page", express("app.get('/login', (req, res) => res.render('login'));\n"), nil},
		{"login deep in the path is not the action", express("app.post('/sys/user/login/setting/userEdit', (req, res) => res.end());\n"), nil},
		{"spring form login disabled", map[string]string{"src/main/java/app/Sec.java": "package app;\nclass Sec {\n  SecurityFilterChain c(HttpSecurity http) throws Exception {\n    return http.formLogin(AbstractHttpConfigurer::disable).httpBasic(b -> b.disable()).build();\n  }\n}\n"}, nil},
		{"spring login with attempt counting", map[string]string{
			"src/main/java/app/Sec.java":      "package app;\nclass Sec {\n  SecurityFilterChain c(HttpSecurity http) throws Exception {\n    return http.formLogin(f -> f.loginPage(\"/login\")).build();\n  }\n}\n",
			"src/main/java/app/Attempts.java": "package app;\nclass LoginAttemptService { int failedAttempts; }\n"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, fs := scanFiles(t, tc.files)
			if got := throttleFindings(fs); !slices.Equal(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Front-end code calls the server's routes; it registers none.
func TestClientCallsAreNotRoutes(t *testing.T) {
	cases := map[string]map[string]string{
		"react component":               {"src/Login.tsx": "import React from 'react';\nimport api from './api';\nexport function Login() { const go = () => api.post('/api/auth/login', { email, password }); return null; }\n"},
		"client held by an object":      {"src/auth.service.ts": "export class AuthService {\n  login(email: string, password: string) { return this.api.post('/auth/login', { email, password }); }\n}\n"},
		"axios instance in server code": {"server.js": "const express = require('express');\nconst axios = require('axios');\nconst api = axios.create({ baseURL: 'http://upstream' });\nasync function sync() { await api.post('/login', { user: 'svc' }); }\n"},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			a, fs := scanFiles(t, files)
			if n := a.RoutesRead(); n != 0 {
				t.Errorf("read %d routes from client code", n)
			}
			if got := throttleFindings(fs); len(got) != 0 {
				t.Errorf("got %q", got)
			}
		})
	}
}

// A Django finding is reported at the view, where @ratelimit goes; Django's
// "reset complete" page consumes no token.
func TestDjangoThrottleLocation(t *testing.T) {
	files := djProject("urlpatterns = [path('login/', views.login_view), path('password/reset/complete/', views.done)]\n",
		"from django.contrib.auth import authenticate\n\ndef login_view(request):\n    user = authenticate(request, username=request.POST['u'], password=request.POST['p'])\n    return None\n\ndef done(request):\n    return None\n")
	_, fs := scanFiles(t, files)
	var got []string
	for _, f := range fs {
		if f.RuleID == BruteForceRuleID || f.RuleID == UnthrottledIssueRuleID {
			got = append(got, fmt.Sprintf("%s %s:%d", f.RuleID, f.Location.FilePath, f.Location.StartLine))
		}
	}
	if want := []string{"AUTHN-002 shop/views.py:3"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	withAxes := djProject("urlpatterns = [path('login/', views.login_view)]\n", "def login_view(request):\n    return None\n",
		"proj/settings.py", "INSTALLED_APPS = ['axes']\n")
	if _, fs := scanFiles(t, withAxes); len(throttleFindings(fs)) != 0 {
		t.Errorf("django-axes limits every login, got %q", throttleFindings(fs))
	}
}
