package authz

import (
	"slices"
	"testing"
)

func routeKeys(a *Analyzer) []string {
	var out []string
	for _, r := range a.Routes() {
		out = append(out, r.Method+" "+r.Path)
	}
	slices.Sort(out)
	return out
}

// The unsafe variants: routes that meet AUTHN-001's proposition.
func TestNextjsMissingAuthenticationLeads(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"app router admin", map[string]string{"app/api/admin/users/route.ts": "import { db } from '@/db';\nexport async function GET() {\n  return Response.json(await db.user.findMany());\n}\n"},
			[]string{"GET /api/admin/users"}},
		{"app router delete by id, route group dropped", map[string]string{"src/app/(api)/api/posts/[id]/route.ts": "export async function DELETE(req: Request, { params }) {\n  await db.post.delete({ where: { id: params.id } });\n  return new Response(null, { status: 204 });\n}\n"},
			[]string{"DELETE /api/posts/:id"}},
		{"const export", map[string]string{"app/api/things/[id]/route.js": "export const PUT = async (req) => Response.json({ ok: true });\n"},
			[]string{"PUT /api/things/:id"}},
		{"pages api admin, any method", map[string]string{"pages/api/admin/export.ts": "export default async function handler(req, res) {\n  res.json(await db.export());\n}\n"},
			[]string{"ALL /api/admin/export"}},
		{"pages api delete", map[string]string{"pages/api/users/[id].ts": "export default async function handler(req, res) {\n  if (req.method === 'DELETE') { await db.user.delete({ where: { id: req.query.id } }); }\n  res.end();\n}\n"},
			[]string{"DELETE /api/users/:id"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			got := authnLeads(a)
			if !slices.Equal(got, c.want) {
				t.Fatalf("leads = %v, want %v (routes %v)", got, c.want, routeKeys(a))
			}
		})
	}
}

// The safe variants: each shows authentication the reader must see, or a
// reason the route is not a lead. None may produce a lead.
func TestNextjsSafeVariantsAreNotLeads(t *testing.T) {
	cases := map[string]map[string]string{
		"next-auth v5 auth() in the handler":  {"app/api/admin/users/route.ts": "import { auth } from '@/auth';\nexport async function GET() {\n  const session = await auth();\n  if (!session) return new Response('no', { status: 401 });\n  return Response.json([]);\n}\n"},
		"getServerSession in a pages handler": {"pages/api/users/[id].ts": "export default async function handler(req, res) {\n  const session = await getServerSession(req, res, authOptions);\n  if (req.method === 'DELETE') { await db.user.delete({ where: { id: req.query.id } }); }\n  res.end();\n}\n"},
		"exported through an auth wrapper":    {"app/api/admin/keys/route.ts": "import { withAuth } from '@/lib/auth';\nexport const GET = withAuth(async (req) => Response.json([]));\n"},
		"default export wrapped":              {"pages/api/admin/reset.ts": "import { requireAuth } from '@/lib/auth';\nexport default requireAuth(async function handler(req, res) { res.end(); });\n"},
		"clerk currentUser":                   {"app/api/accounts/[id]/route.ts": "import { currentUser } from '@clerk/nextjs/server';\nexport async function PATCH(req) {\n  const user = await currentUser();\n  return Response.json({});\n}\n"},
		"middleware guards the app": {
			"middleware.ts":                "export { default } from 'next-auth/middleware';\nexport const config = { matcher: ['/api/admin/:path*'] };\n",
			"app/api/admin/users/route.ts": "export async function GET() { return Response.json([]); }\n",
		},
		"public by name":                {"app/api/auth/login/route.ts": "export async function POST(req) { return Response.json({}); }\n"},
		"health":                        {"app/api/health/route.ts": "export async function GET() { return Response.json({ ok: true }); }\n"},
		"a test fixture":                {"tests/app/api/admin/users/route.ts": "export async function GET() { return Response.json([]); }\n"},
		"no verb exported, not a route": {"app/api/admin/users/route.ts": "export const dynamic = 'force-dynamic';\nfunction helper() {}\n"},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			a, _ := scanFiles(t, files)
			if got := authnLeads(a); len(got) != 0 {
				t.Fatalf("a safe variant produced leads %v (routes %v)", got, routeKeys(a))
			}
		})
	}
}

func TestNextjsRouteTable(t *testing.T) {
	a, _ := scanFiles(t, map[string]string{
		"app/(shop)/api/orders/[orderId]/route.ts": "import { auth } from '@/auth';\nexport async function GET() { const s = await auth(); return Response.json({}); }\nexport async function POST() { return Response.json({}); }\n",
		"app/api/files/[...path]/route.ts":         "export async function GET() { return Response.json({}); }\n",
		"pages/api/index.ts":                       "export default function handler(req, res) { res.end(); }\n",
		"pages/api/ping.ts":                        "export default function handler(req, res) { if (req.method !== 'POST') return res.status(405).end(); res.end(); }\n",
	})
	want := []string{"ALL /api", "GET /api/files/*path", "GET /api/orders/:orderId", "POST /api/orders/:orderId", "POST /api/ping"}
	if got := routeKeys(a); !slices.Equal(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	for _, r := range a.Routes() {
		if r.Method == "GET" && r.Path == "/api/orders/:orderId" && r.Authn == "" {
			t.Error("the GET handler reads auth(); its route must record authentication")
		}
	}
	if a.RoutesRead() != len(a.Routes()) {
		t.Errorf("RoutesRead %d != %d", a.RoutesRead(), len(a.Routes()))
	}
}

func TestNextjsUnverifiedStripeWebhook(t *testing.T) {
	_, fs := scanFiles(t, map[string]string{"app/api/webhooks/stripe/route.ts": "export async function POST(req: Request) {\n  const event = await req.json();\n  if (event.type === 'checkout.session.completed') { await fulfil(event); }\n  return new Response('ok');\n}\n"})
	if got := webhookFindings(fs); !slices.Equal(got, []string{"POST /api/webhooks/stripe"}) {
		t.Fatalf("unsigned stripe webhook findings = %v", got)
	}
	_, fs = scanFiles(t, map[string]string{"app/api/webhooks/stripe/route.ts": "export async function POST(req: Request) {\n  const body = await req.text();\n  const event = stripe.webhooks.constructEvent(body, req.headers.get('stripe-signature')!, secret);\n  return new Response('ok');\n}\n"})
	if got := webhookFindings(fs); len(got) != 0 {
		t.Fatalf("a verified stripe webhook must not be reported: %v", got)
	}
}
