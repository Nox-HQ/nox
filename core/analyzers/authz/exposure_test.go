package authz

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// scanFiles writes files into a temp repository and runs the analyzer over it.
func scanFiles(t *testing.T, files map[string]string, enable ...string) (*Analyzer, []findings.Finding) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	arts, err := discovery.NewWalker(dir).Walk()
	if err != nil {
		t.Fatal(err)
	}
	a := NewAnalyzer()
	a.EnableOptIn(enable)
	fs, err := a.ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatal(err)
	}
	return a, fs.Findings()
}

// authnLeads returns "METHOD path" for every missing-authentication lead.
func authnLeads(a *Analyzer) []string {
	var out []string
	for _, l := range a.Leads() {
		if l.RuleID == AuthnRuleID {
			out = append(out, l.Method+" "+l.Path)
		}
	}
	slices.Sort(out)
	return out
}

func webhookFindings(fs []findings.Finding) []string {
	var out []string
	for _, f := range fs {
		if f.RuleID == WebhookRuleID {
			out = append(out, f.Metadata["route"])
		}
	}
	slices.Sort(out)
	return out
}

const expressHead = "const express = require('express');\nconst app = express();\nconst db = require('./db');\n"

func express(body string) map[string]string {
	return map[string]string{"server.js": expressHead + body + "app.listen(3000);\n"}
}

// ---- AUTHN-001: routes with no visible authentication ----

func TestMissingAuthenticationLeads(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"express admin route", express("app.get('/api/admin/users', async (req, res) => { res.json(await db.query('select * from users')); });\n"),
			[]string{"GET /api/admin/users"}},
		{"express delete by id", express("app.delete('/api/users/:id', async (req, res) => { await db.query('delete from users where id=$1', [req.params.id]); res.end(); });\n"),
			[]string{"DELETE /api/users/:id"}},
		{"express put", express("app.put('/api/things/:id', (req, res) => { res.end(); });\n"),
			[]string{"PUT /api/things/:id"}},
		{"route registered before the app-wide gate", express(
			"app.get('/api/admin/users', (req, res) => res.json([]));\napp.use(requireAuth);\napp.get('/api/admin/roles', (req, res) => res.json([]));\n"),
			[]string{"GET /api/admin/users"}},
		{"fastify admin route", map[string]string{"s.js": "const fastify = require('fastify')();\nfastify.get('/admin/users', async (request, reply) => { return []; });\n"},
			[]string{"GET /admin/users"}},
		{"flask admin route", map[string]string{"app.py": "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/api/admin/users')\ndef users():\n    return 'x'\n"},
			[]string{"GET /api/admin/users"}},
		{"flask delete", map[string]string{"app.py": "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/api/notes/<int:note_id>', methods=['DELETE'])\ndef rm(note_id):\n    return 'x'\n"},
			[]string{"DELETE /api/notes/<int:note_id>"}},
		{"get of a record by id", express("app.get('/api/invoices/:id', (req, res) => res.json({}));\n"),
			[]string{"GET /api/invoices/:id"}},
		{"fastapi delete", map[string]string{"app.py": "from fastapi import FastAPI\napp = FastAPI()\n\n@app.delete('/users/{user_id}')\nasync def rm(user_id: int):\n    return {}\n"},
			[]string{"DELETE /users/{user_id}"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, fs := scanFiles(t, c.files)
			if got := authnLeads(a); !slices.Equal(got, c.want) {
				t.Errorf("authentication leads = %v, want %v", got, c.want)
			}
			for _, f := range fs {
				if f.RuleID == AuthnRuleID {
					t.Errorf("AUTHN-001 reported a finding without being enabled: %s", f.Message)
				}
			}
		})
	}
}

// Each counterexample is a way the source shows the caller is authenticated, or
// that the route is public on purpose. None may be a lead.
func TestAuthenticationCounterexamplesAreNotLeads(t *testing.T) {
	adminJSON := "(req, res) => res.json([])"
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"app-wide middleware", express("app.use(requireAuth);\napp.get('/api/admin/users', " + adminJSON + ");\napp.delete('/api/users/:id', " + adminJSON + ");\n")},
		{"app-wide passport", express("app.use(passport.authenticate('jwt', { session: false }));\napp.get('/api/admin/users', " + adminJSON + ");\n")},
		{"route-level middleware", express("app.get('/api/admin/users', requireAuth, " + adminJSON + ");\n")},
		{"role middleware", express("app.delete('/api/users/:id', requireRole('admin'), " + adminJSON + ");\n")},
		{"prefix middleware", express("app.use('/api/admin', requireAuth);\napp.get('/api/admin/users', " + adminJSON + ");\n")},
		{"router-level middleware", map[string]string{
			"server.js": expressHead + "app.use('/api/admin', require('./admin'));\n",
			"admin.js":  "const express = require('express');\nconst router = express.Router();\nrouter.use(requireAuth);\nrouter.get('/users', (req, res) => res.json([]));\nmodule.exports = router;\n",
		}},
		{"auth at the mount", map[string]string{
			"server.js": expressHead + "app.use('/api/admin', requireAuth, require('./admin'));\n",
			"admin.js":  "const express = require('express');\nconst router = express.Router();\nrouter.get('/users', (req, res) => res.json([]));\nmodule.exports = router;\n",
		}},
		{"app-wide auth above an unresolved router", map[string]string{
			"server.js": expressHead + "app.use(requireAuth);\napp.use('/api', routes);\n",
			"admin.js":  "const express = require('express');\nconst router = express.Router();\nrouter.get('/admin/users', (req, res) => res.json([]));\nmodule.exports = router;\n",
		}},
		{"inline 401", express("app.get('/api/admin/users', (req, res) => {\n  if (!req.user) return res.status(401).end();\n  res.json([]);\n});\n")},
		{"inline bearer token", express("app.delete('/api/users/:id', (req, res) => {\n  const t = req.headers.authorization;\n  jwt.verify(t, secret);\n  res.end();\n});\n")},
		{"login route", express("app.put('/api/login', " + adminJSON + ");\n")},
		{"health route", express("app.get('/api/admin/health', " + adminJSON + ");\n")},
		{"not sensitive and not mutating", express("app.get('/api/products', " + adminJSON + ");\napp.post('/api/search', " + adminJSON + ");\n")},
		{"a public directory listing", express("app.get('/api/users', " + adminJSON + ");\napp.get('/api/orders', " + adminJSON + ");\n")},
		{"guard registered for a route served elsewhere", express("app.delete('/api/Users/:id', security.denyAll());\napp.get('/api/Users/:id', security.isAuthorized());\n")},
		{"a feed", express("app.get('/user/:slug/topics.rss', " + adminJSON + ");\n")},
		{"example code", map[string]string{"examples/admin/index.js": expressHead + "app.get('/admin/users', " + adminJSON + ");\n"}},
		{"test code", map[string]string{"test/app.js": expressHead + "app.delete('/users/:id', " + adminJSON + ");\n"}},
		{"browser code", map[string]string{"public/src/users.js": "const api = require('api');\napi.put('/users/1/ban', {});\n"}},
		{"webhook receiver", express("app.put('/api/webhooks/billing', " + adminJSON + ");\n")},
		{"flask login_required", map[string]string{"app.py": "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/api/admin/users')\n@login_required\ndef users():\n    return 'x'\n"}},
		{"flask jwt_required", map[string]string{"app.py": "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/api/admin/users')\n@jwt_required()\ndef users():\n    return 'x'\n"}},
		{"flask before_request gate", map[string]string{"app.py": "from flask import Flask, request, abort\napp = Flask(__name__)\n\n@app.before_request\ndef gate():\n    if not request.headers.get('Authorization'):\n        abort(401)\n\n@app.route('/api/admin/users')\ndef users():\n    return 'x'\n"}},
		{"flask inline session check", map[string]string{"app.py": "from flask import Flask, session, abort\napp = Flask(__name__)\n\n@app.route('/api/admin/users')\ndef users():\n    if 'uid' not in session:\n        abort(401)\n    return 'x'\n"}},
		{"fastapi Depends on a parameter", map[string]string{"app.py": "from fastapi import FastAPI, Depends\napp = FastAPI()\n\n@app.delete('/users/{user_id}')\nasync def rm(user_id: int, user=Depends(get_current_user)):\n    return {}\n"}},
		{"fastapi router-level dependency", map[string]string{"app.py": "from fastapi import APIRouter, Depends\nrouter = APIRouter(dependencies=[Depends(get_current_user)])\n\n@router.delete('/users/{user_id}')\nasync def rm(user_id: int):\n    return {}\n"}},
		{"fastapi security scheme", map[string]string{"app.py": "from fastapi import FastAPI, Security\napp = FastAPI()\n\n@app.get('/admin/users')\nasync def users(token: str = Security(oauth2_scheme)):\n    return []\n"}},
		{"fastapi global middleware this reader cannot evaluate", map[string]string{"app.py": "from fastapi import FastAPI\napp = FastAPI()\napp.add_middleware(AuthMiddleware)\n\n@app.delete('/users/{user_id}')\nasync def rm(user_id: int):\n    return {}\n"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := authnLeads(a); len(got) != 0 {
				t.Errorf("counterexample produced authentication leads: %v", got)
			}
		})
	}
}

// Enabled, AUTHN-001 reports findings and holds no lead for them.
func TestAuthenticationFindingsWhenEnabled(t *testing.T) {
	a, fs := scanFiles(t, express("app.get('/api/admin/users', (req, res) => res.json([]));\n"), AuthnRuleID)
	var got []findings.Finding
	for _, f := range fs {
		if f.RuleID == AuthnRuleID {
			got = append(got, f)
		}
	}
	if len(got) != 1 || got[0].Metadata["route"] != "GET /api/admin/users" || got[0].Metadata["cwe"] != "CWE-306" {
		t.Fatalf("findings = %+v", got)
	}
	if l := authnLeads(a); len(l) != 0 {
		t.Errorf("an enabled rule also held leads: %v", l)
	}
}

// The model and the lead share one fact: a route whose handler checks the
// caller itself is recorded as authenticated, not as "none visible".
func TestInventoryRecordsInlineAuthentication(t *testing.T) {
	rs := routesOf(t, express("app.get('/api/admin/users', (req, res) => {\n  if (!req.user) return res.status(401).end();\n  res.json([]);\n});\napp.get('/api/admin/roles', (req, res) => res.json([]));\n"))
	by := map[string]string{}
	for _, r := range rs {
		by[r.Path] = r.Authn
	}
	if by["/api/admin/users"] == "" || by["/api/admin/roles"] != "" {
		t.Errorf("authn by path = %v", by)
	}
}

// Flask converters (`<int:id>`, `<path:p>`, `<uuid:u>`) must not hide a route
// from AUTHZ-001: the converter is part of the rule, not of the parameter name.
func TestFlaskConvertersDoNotHideTheLead(t *testing.T) {
	for _, conv := range []string{"", "int:", "path:", "uuid:", "string:", "int(min=1):"} {
		src := "from flask import Flask, jsonify\nimport sqlite3\napp = Flask(__name__)\n\n" +
			"@app.route('/api/invoices/<" + conv + "invoice_id>')\n@login_required\ndef invoice(invoice_id):\n" +
			"    db = sqlite3.connect('x.db')\n    row = db.execute('SELECT * FROM invoices WHERE id = ?', (invoice_id,)).fetchone()\n    return jsonify(row)\n"
		a, _ := scanFiles(t, map[string]string{"app.py": src})
		var got int
		for _, l := range a.Leads() {
			if l.RuleID == "" && strings.HasPrefix(l.Path, "/api/invoices/") {
				got++
			}
		}
		if got != 1 {
			t.Errorf("converter %q: %d object-level leads, want 1", conv, got)
		}
	}
}

// ---- WEBHOOK-001: webhook payload accepted without signature verification ----

func TestUnsignedWebhooksAreReported(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"stripe, JSON.parse of the body", express("app.post('/webhooks/stripe', express.raw({ type: '*/*' }), (req, res) => {\n  const event = JSON.parse(req.body);   // no signature verification, constructEvent missing\n  res.json({ received: true, type: event.type });\n});\n"),
			[]string{"POST /webhooks/stripe"}},
		{"stripe, recognised by its event types", express("app.post('/hooks/payments', (req, res) => {\n  const event = req.body;\n  if (event.type === 'checkout.session.completed') { fulfil(event); }\n  res.end();\n});\n"),
			[]string{"POST /hooks/payments"}},
		{"stripe, handler in another file", map[string]string{
			"server.js": expressHead + "const { handle } = require('./stripe');\napp.post('/stripe/webhook', handle);\n",
			"stripe.js": "exports.handle = (req, res) => {\n  const event = req.body;\n  res.json({ ok: event.type });\n};\n",
		}, []string{"POST /stripe/webhook"}},
		{"stripe, python", map[string]string{"app.py": "from flask import Flask, request\nimport json\napp = Flask(__name__)\n\n@app.route('/webhooks/stripe', methods=['POST'])\ndef hook():\n    event = json.loads(request.data)\n    return 'ok'\n"},
			[]string{"POST /webhooks/stripe"}},
		{"github reads the event header but not the signature", express("app.post('/gh', (req, res) => {\n  const ev = req.headers['x-github-event'];\n  res.end(ev);\n});\n"),
			[]string{"POST /gh"}},
		{"github by path", express("app.post('/github/webhook', (req, res) => { res.end(); });\n"),
			[]string{"POST /github/webhook"}},
		{"slack events", express("app.post('/slack/events', (req, res) => {\n  if (req.body.type === 'url_verification') return res.send(req.body.challenge);\n  res.end();\n});\n"),
			[]string{"POST /slack/events"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, fs := scanFiles(t, c.files)
			if got := webhookFindings(fs); !slices.Equal(got, c.want) {
				t.Errorf("webhook findings = %v, want %v", got, c.want)
			}
			for _, f := range fs {
				if f.RuleID == WebhookRuleID && !strings.Contains(f.Message, "webhook payload accepted without signature verification") && !strings.Contains(f.Message, "Webhook payload accepted without signature verification") {
					t.Errorf("message does not make the precise claim: %s", f.Message)
				}
			}
		})
	}
}

// A webhook that verifies, by any route the source shows, is not reported.
func TestVerifiedWebhooksAreNotReported(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"stripe constructEvent", express("app.post('/webhooks/stripe', express.raw({ type: '*/*' }), (req, res) => {\n  const event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], secret);\n  res.json({ received: true });\n});\n")},
		{"stripe constructEvent in a helper", map[string]string{
			"server.js": expressHead + "const { parse } = require('./verify');\napp.post('/webhooks/stripe', (req, res) => {\n  const event = parse(req);\n  res.json({ t: event.type });\n});\n",
			"verify.js": "exports.parse = (req) => stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.WHSEC);\n",
		}},
		{"stripe verification middleware", express("app.post('/webhooks/stripe', verifyStripeSignature, (req, res) => { res.end(); });\n")},
		{"stripe, named handler with constructEvent", express("function handle(req, res) {\n  const e = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], s);\n  res.end();\n}\napp.post('/webhooks/stripe', handle);\n")},
		{"stripe python construct_event", map[string]string{"app.py": "from flask import Flask, request\nimport stripe\napp = Flask(__name__)\n\n@app.route('/webhooks/stripe', methods=['POST'])\ndef hook():\n    event = stripe.Webhook.construct_event(request.data, request.headers['Stripe-Signature'], SECRET)\n    return 'ok'\n"}},
		{"stripe python, verification in a helper", map[string]string{"app.py": "from flask import Flask, request\nimport stripe\napp = Flask(__name__)\n\ndef parse_event():\n    return stripe.Webhook.construct_event(request.data, request.headers['Stripe-Signature'], SECRET)\n\n@app.route('/webhooks/stripe', methods=['POST'])\ndef hook():\n    event = parse_event()\n    return 'ok'\n"}},
		{"fastapi stripe-signature header parameter", map[string]string{"app.py": "from fastapi import FastAPI, Request, Header\nimport stripe\napp = FastAPI()\n\n@app.post('/webhooks/stripe')\nasync def hook(request: Request, stripe_signature: str = Header(None)):\n    payload = await request.body()\n    event = stripe.Webhook.construct_event(payload, stripe_signature, SECRET)\n    return {}\n"}},
		{"github hmac", express("app.post('/github/webhook', (req, res) => {\n  const sig = req.headers['x-hub-signature-256'];\n  const mac = crypto.createHmac('sha256', secret).update(req.rawBody).digest('hex');\n  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from('sha256=' + mac))) return res.status(401).end();\n  res.end();\n});\n")},
		{"github python compare_digest", map[string]string{"app.py": "from flask import Flask, request\nimport hmac\napp = Flask(__name__)\n\n@app.route('/gh', methods=['POST'])\ndef hook():\n    ev = request.headers.get('X-GitHub-Event')\n    sig = request.headers.get('X-Hub-Signature-256')\n    if not hmac.compare_digest(sig, expected(request.data)):\n        return 'no', 401\n    return 'ok'\n"}},
		{"slack signing secret", express("app.post('/slack/events', (req, res) => {\n  const sig = req.headers['x-slack-signature'];\n  verifySlack(sig, req.headers['x-slack-request-timestamp'], req.rawBody);\n  res.end();\n});\n")},
		{"not a post", express("app.get('/webhooks/stripe', (req, res) => { res.end('ok'); });\n")},
		{"a webhook of no known provider", express("app.post('/webhooks/custom', (req, res) => { res.end(); });\n")},
		{"handler that cannot be read", express("app.post('/webhooks/stripe', somethingDynamic());\n")},
		{"a path that only mentions the provider", express("app.post('/api/stripe/checkout', (req, res) => { res.end(); });\n")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, fs := scanFiles(t, c.files)
			if got := webhookFindings(fs); len(got) != 0 {
				t.Errorf("reported a webhook that verifies or is not a receiver: %v", got)
			}
		})
	}
}

// A comment that names the verification is not verification.
func TestACommentIsNotAVerification(t *testing.T) {
	_, fs := scanFiles(t, express("app.post('/webhooks/stripe', (req, res) => {\n  // TODO: stripe.webhooks.constructEvent(req.body, sig, secret) and check stripe-signature\n  const e = JSON.parse(req.body);\n  res.end();\n});\n"))
	if got := webhookFindings(fs); len(got) != 1 {
		t.Errorf("a commented-out verification cleared the finding: %v", got)
	}
}

func TestNewRulesAreDeclared(t *testing.T) {
	byID := map[string]bool{}
	optIn := map[string]bool{}
	for _, r := range NewAnalyzer().Rules().Rules() {
		byID[r.ID] = true
		optIn[r.ID] = r.OptIn
	}
	for _, id := range []string{RuleID, AuthnRuleID, WebhookRuleID} {
		if !byID[id] {
			t.Errorf("%s is not declared", id)
		}
	}
	if !optIn[AuthnRuleID] || optIn[WebhookRuleID] {
		t.Errorf("AUTHN-001 is a lead unless enabled and WEBHOOK-001 reports by default: opt-in = %v", optIn)
	}
}
