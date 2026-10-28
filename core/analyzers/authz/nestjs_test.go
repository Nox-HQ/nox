package authz

import (
	"slices"
	"testing"
)

const nestHead = "import { Controller, Get, Post, Put, Patch, Delete, UseGuards } from '@nestjs/common';\n"

func nestFile(name, body string) map[string]string {
	return map[string]string{"src/" + name + ".controller.ts": nestHead + body}
}

// The unsafe variants: Nest routes that meet AUTHN-001's proposition.
func TestNestMissingAuthenticationLeads(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"delete by id", nestFile("users", "@Controller('users')\nexport class UsersController {\n  @Delete(':id')\n  remove(@Param('id') id: string) { return this.users.remove(id); }\n}\n"),
			[]string{"DELETE /users/:id"}},
		{"admin controller", nestFile("admin", "@Controller('admin/reports')\nexport class AdminController {\n  @Get()\n  list() { return []; }\n}\n"),
			[]string{"GET /admin/reports"}},
		{"object form with global prefix", map[string]string{
			"src/main.ts":              "import { NestFactory } from '@nestjs/core';\nasync function bootstrap() { const app = await NestFactory.create(AppModule); app.setGlobalPrefix('api'); await app.listen(3000); }\n",
			"src/orders.controller.ts": nestHead + "@Controller({ path: 'orders' })\nexport class OrdersController {\n  @Put(':id')\n  update() {}\n}\n"},
			[]string{"PUT /api/orders/:id"}},
		{"throttler is not authentication", nestFile("keys", "@Controller('keys')\n@UseGuards(ThrottlerGuard)\nexport class KeysController {\n  @Patch(':id')\n  rotate() {}\n}\n"),
			[]string{"PATCH /keys/:id"}},
		{"decorators on separate lines without semicolons", nestFile("x", "@Controller('accounts')\nexport class AccountsController {\n  @Post()\n  @HttpCode(200)\n  create() {}\n\n  @Delete(':id')\n  @HttpCode(204)\n  remove() {}\n}\n"),
			[]string{"DELETE /accounts/:id"}},
		{"the guard sits on another controller", map[string]string{
			"src/a.controller.ts": nestHead + "@Controller('safe')\n@UseGuards(JwtAuthGuard)\nexport class A {\n  @Delete(':id')\n  r() {}\n}\n",
			"src/b.controller.ts": nestHead + "@Controller('other')\nexport class B {\n  @Delete(':id')\n  r() {}\n}\n"},
			[]string{"DELETE /other/:id"}},
		{"a public decorator on a sibling does not cover the route", nestFile("c", "@Controller('things')\nexport class C {\n  @Public()\n  @Get('open')\n  open() {}\n\n  @Delete(':id')\n  del() {}\n}\n"),
			[]string{"DELETE /things/:id"}},
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

// The safe variants: none may produce a lead.
func TestNestSafeVariantsAreNotLeads(t *testing.T) {
	del := "  @Delete(':id')\n  remove() {}\n}\n"
	cases := map[string]map[string]string{
		"class-level guard":                     nestFile("a", "@Controller('users')\n@UseGuards(JwtAuthGuard)\nexport class A {\n"+del),
		"passport AuthGuard":                    nestFile("b", "@Controller('users')\n@UseGuards(AuthGuard('jwt'))\nexport class B {\n"+del),
		"method-level guard":                    nestFile("c", "@Controller('users')\nexport class C {\n  @UseGuards(JwtAuthGuard)\n  @Delete(':id')\n  remove() {}\n}\n"),
		"guards listed, one of them auth":       nestFile("d", "@Controller('users')\n@UseGuards(ThrottlerGuard, JwtAuthGuard, RolesGuard)\nexport class D {\n"+del),
		"roles guard only (authorization seen)": nestFile("e", "@Controller('users')\n@UseGuards(RolesGuard)\nexport class E {\n"+del),
		"unnameable custom guard":               nestFile("f", "@Controller('users')\n@UseGuards(SessionChecker)\nexport class F {\n"+del),
		"public on purpose":                     nestFile("g", "@Controller('users')\nexport class G {\n  @Public()\n  @Delete(':id')\n  remove() {}\n}\n"),
		"reads the caller":                      nestFile("h", "@Controller('users')\nexport class H {\n  @Delete(':id')\n  remove(@CurrentUser() user: User) {}\n}\n"),
		"reads req.user":                        nestFile("i", "@Controller('users')\nexport class I {\n  @Delete(':id')\n  remove(@Req() req) { return this.s.remove(req.user.id); }\n}\n"),
		"global guard via useGlobalGuards": {
			"src/main.ts":         "import { NestFactory } from '@nestjs/core';\nconst app = await NestFactory.create(AppModule);\napp.useGlobalGuards(new JwtAuthGuard(reflector));\n",
			"src/j.controller.ts": nestHead + "@Controller('users')\nexport class J {\n" + del},
		"global guard via APP_GUARD": {
			"src/app.module.ts":   "import { Module } from '@nestjs/common';\nimport { APP_GUARD } from '@nestjs/core';\n@Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })\nexport class AppModule {}\n",
			"src/k.controller.ts": nestHead + "@Controller('users')\nexport class K {\n" + del},
		"middleware applied through configure": {
			"src/app.module.ts":   "import { Module } from '@nestjs/common';\nexport class AppModule { configure(consumer) { consumer.apply(SessionLoader).forRoutes('*'); } }\n",
			"src/l.controller.ts": nestHead + "@Controller('users')\nexport class L {\n" + del},
		"a fastify hook": {
			"src/main.ts":         "import { NestFactory } from '@nestjs/core';\nconst app = await NestFactory.create(AppModule, new FastifyAdapter());\napp.getHttpAdapter().getInstance().addHook('onRequest', verify);\n",
			"src/m.controller.ts": nestHead + "@Controller('users')\nexport class M {\n" + del},
		"a test fixture": {"test/fixtures/n.controller.ts": nestHead + "@Controller('users')\nexport class N {\n" + del},
		// Counterexamples: the same decorators from another framework.
		"routing-controllers, not Nest": {"src/o.controller.ts": "import { Controller, Delete } from 'routing-controllers';\n@Controller('/users')\nexport class O {\n  @Delete('/:id')\n  remove() {}\n}\n"},
		"constant path is not guessed":  nestFile("p", "@Controller(ROUTES.USERS)\nexport class P {\n"+del),
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

func TestNestRouteTable(t *testing.T) {
	a, _ := scanFiles(t, map[string]string{
		"src/main.ts": "import { NestFactory } from '@nestjs/core';\nconst app = await NestFactory.create(AppModule);\napp.setGlobalPrefix('api');\napp.enableVersioning({ type: VersioningType.URI });\napp.useGlobalGuards(new JwtAuthGuard());\n",
		"src/cats.controller.ts": nestHead + `@Controller({ path: 'cats', version: '1' })
export class CatsController {
  constructor(private readonly cats: CatsService) {}

  @Get()
  findAll() {}

  @Public()
  @Get('health')
  health() {}

  @Post([ 'a', 'b' ])
  @UseGuards(RolesGuard)
  create(@Body() dto: CreateCatDto) {}
}
`,
	})
	want := []string{"GET /api/v1/cats", "GET /api/v1/cats/health", "POST /api/v1/cats/a", "POST /api/v1/cats/b"}
	if got := routeKeys(a); !slices.Equal(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	for _, r := range a.Routes() {
		if r.Reader != ReaderNestJS {
			t.Errorf("%s %s Reader = %q, want NestJS", r.Method, r.Path, r.Reader)
		}
		switch r.Path {
		case "/api/v1/cats":
			if r.Authn == "" {
				t.Error("the global guard must be recorded as the route's authentication")
			}
		case "/api/v1/cats/health":
			if r.Authn != "" {
				t.Errorf("a @Public() route must not claim the global guard: %q", r.Authn)
			}
		case "/api/v1/cats/a":
			if r.Authz == "" {
				t.Error("RolesGuard is authorization")
			}
		}
	}
	if a.RoutesRead() != len(a.Routes()) {
		t.Errorf("RoutesRead %d != %d", a.RoutesRead(), len(a.Routes()))
	}
}

func TestNestUnverifiedStripeWebhook(t *testing.T) {
	_, fs := scanFiles(t, nestFile("stripe", "@Controller('webhooks/stripe')\nexport class StripeController {\n  @Post()\n  handle(@Body() event: any) {\n    if (event.type === 'checkout.session.completed') { this.logger.log('x'); }\n  }\n}\n"))
	if got := webhookFindings(fs); !slices.Equal(got, []string{"POST /webhooks/stripe"}) {
		t.Fatalf("unsigned stripe webhook findings = %v", got)
	}
	// Verified in the handler.
	_, fs = scanFiles(t, nestFile("stripe", "@Controller('webhooks/stripe')\nexport class StripeController {\n  @Post()\n  handle(@Req() req, @Headers('stripe-signature') sig: string) {\n    return this.stripe.webhooks.constructEvent(req.rawBody, sig, secret);\n  }\n}\n"))
	if got := webhookFindings(fs); len(got) != 0 {
		t.Fatalf("a verified webhook must not be reported: %v", got)
	}
	// Verified in the injected service the handler delegates to.
	_, fs = scanFiles(t, map[string]string{
		"src/stripe.controller.ts": nestHead + "@Controller('webhooks/stripe')\nexport class StripeController {\n  constructor(private readonly billing: BillingService) {}\n  @Post()\n  handle(@Req() req) { return this.billing.process(req); }\n}\n",
		"src/billing.service.ts":   "import { Injectable } from '@nestjs/common';\n@Injectable()\nexport class BillingService {\n  process(req) { return stripe.webhooks.constructEvent(req.rawBody, req.headers['stripe-signature'], s); }\n}\n",
	})
	if got := webhookFindings(fs); len(got) != 0 {
		t.Fatalf("verification in the delegated service must be seen: %v", got)
	}
	// Delegated to a service this reader cannot read: silence, not a finding.
	_, fs = scanFiles(t, nestFile("stripe", "@Controller('webhooks/stripe')\nexport class StripeController {\n  constructor(private readonly billing: BillingService) {}\n  @Post()\n  handle(@Req() req) { return this.billing.process(req); }\n}\n"))
	if got := webhookFindings(fs); len(got) != 0 {
		t.Fatalf("an unreadable delegate must not become a finding: %v", got)
	}
	// Verified by a decorator or guard that says what it verifies.
	for name, body := range map[string]string{
		"decorator": "@Controller('webhooks/stripe')\nexport class S {\n  @Post()\n  @VerifyWebhook('stripe')\n  handle(@Body() e: any) { if (e.type === 'checkout.session.completed') {} }\n}\n",
		"guard":     "@Controller('webhooks/stripe')\n@UseGuards(StripeSignatureGuard)\nexport class S {\n  @Post()\n  handle(@Body() e: any) { if (e.type === 'checkout.session.completed') {} }\n}\n",
	} {
		_, fs = scanFiles(t, nestFile("stripe", body))
		if got := webhookFindings(fs); len(got) != 0 {
			t.Fatalf("%s: a webhook verified by name must not be reported: %v", name, got)
		}
	}
}

// A repository can hold several applications. A guard or prefix registered in
// one governs only its own controllers; it must not be recorded as the
// authentication of a controller elsewhere, and it must not turn that
// controller into a lead either, because this reader cannot be sure which
// application a shared library controller belongs to.
func TestNestDeclarationsAreScopedToTheirApplication(t *testing.T) {
	del := "@Controller('users')\nexport class C {\n  @Delete(':id')\n  remove() {}\n}\n"
	a, _ := scanFiles(t, map[string]string{
		"apps/api/src/main.ts":                "import { NestFactory } from '@nestjs/core';\nconst app = await NestFactory.create(M);\napp.setGlobalPrefix('v9');\napp.useGlobalGuards(new JwtAuthGuard());\n",
		"apps/api/src/users.controller.ts":    nestHead + del,
		"apps/worker/src/users.controller.ts": nestHead + del,
	})
	got := map[string]string{}
	for _, r := range a.Routes() {
		got[r.FilePath] = r.Method + " " + r.Path + " | " + r.Authn
	}
	if want := "DELETE /v9/users/:id | global guard JwtAuthGuard"; got["apps/api/src/users.controller.ts"] != want {
		t.Errorf("api route = %q, want %q", got["apps/api/src/users.controller.ts"], want)
	}
	if want := "DELETE /users/:id | "; got["apps/worker/src/users.controller.ts"] != want {
		t.Errorf("worker route = %q, want %q (another application's guard and prefix must not apply)", got["apps/worker/src/users.controller.ts"], want)
	}
	if leads := authnLeads(a); len(leads) != 0 {
		t.Errorf("a controller beside a guarded application is silent, got leads %v", leads)
	}
}
