package authz

import (
	"slices"
	"testing"
)

const actixHead = "use actix_web::{get, post, put, delete, web, App, HttpServer, HttpResponse, Responder};\n\n"

// handlers are three functions with attribute macros, so a case only has to
// say how they are registered.
const actixHandlers = `#[get("/health")]
async fn health() -> impl Responder { HttpResponse::Ok() }

#[delete("/users/{id}")]
async fn del_user(path: web::Path<u32>) -> impl Responder { HttpResponse::Ok() }

#[post("/orders")]
async fn create_order() -> impl Responder { HttpResponse::Ok() }

`

func actixApp(registration string) map[string]string {
	return map[string]string{"src/main.rs": actixHead + actixHandlers + "async fn stats() -> impl Responder { HttpResponse::Ok() }\n" +
		"fn main() {\n    HttpServer::new(|| {\n        " + registration + "\n    });\n}\n"}
}

func TestActixRouteTable(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"attribute macros that are registered", actixApp("App::new().service(health).service(del_user).service(create_order)"),
			[]string{"DELETE /users/{id}", "GET /health", "POST /orders"}},
		{"a handler nothing registers is not a route", actixApp("App::new().service(health)"),
			[]string{"GET /health"}},
		{"qualified attribute and route attribute", map[string]string{"src/main.rs": actixHead +
			"#[actix_web::put(\"/a/{id}\")]\nasync fn a() -> impl Responder { \"\" }\n" +
			"#[route(\"/b\", method = \"GET\", method = \"PATCH\")]\nasync fn b() -> impl Responder { \"\" }\n" +
			"fn main() { App::new().service(a).service(b); }\n"},
			[]string{"GET /b", "PATCH /b", "PUT /a/{id}"}},
		{"scopes prefix their services, nested too", actixApp("App::new().service(web::scope(\"/api\").service(del_user).service(web::scope(\"/v1\").service(create_order)))"),
			[]string{"DELETE /api/users/{id}", "POST /api/v1/orders"}},
		{"resource with routes", actixApp("App::new().service(web::resource(\"/items/{id}\").route(web::get().to(stats)).route(web::delete().to(stats)))"),
			[]string{"DELETE /items/{id}", "GET /items/{id}"}},
		{"resource to() answers every method", actixApp("App::new().service(web::resource(\"/any\").to(stats))"),
			[]string{"ALL /any"}},
		{"route on the app and on a scope", actixApp("App::new().route(\"/admin/stats\", web::get().to(stats)).service(web::scope(\"/api\").route(\"/p\", web::put().to(stats)))"),
			[]string{"GET /admin/stats", "PUT /api/p"}},
		{"a tuple of services", actixApp("App::new().service((health, create_order))"),
			[]string{"GET /health", "POST /orders"}},
		{"configure function bound by the app and a scope", map[string]string{"src/main.rs": actixHead +
			"fn config(cfg: &mut web::ServiceConfig) {\n    cfg.route(\"/c\", web::delete().to(h));\n    cfg.service(web::resource(\"/d\").route(web::post().to(h)));\n}\n" +
			"fn main() { App::new().service(web::scope(\"/x\").configure(config)); }\n"},
			[]string{"DELETE /x/c", "POST /x/d"}},
		{"handler of another module resolved by its path", map[string]string{
			"src/main.rs":  actixHead + "mod users;\nfn main() { App::new().service(users::list); }\n",
			"src/users.rs": "use actix_web::get;\n#[get(\"/users\")]\npub async fn list() -> String { String::new() }\n"},
			[]string{"GET /users"}},
		{"a handler name two modules share is not guessed", map[string]string{
			"src/main.rs": actixHead + "fn main() { App::new().service(index); }\n",
			"src/a.rs":    "use actix_web::get;\n#[get(\"/a\")]\npub async fn index() -> String { String::new() }\n",
			"src/b.rs":    "use actix_web::get;\n#[get(\"/b\")]\npub async fn index() -> String { String::new() }\n"}, nil},
		{"inline modules sharing a handler name are not guessed", map[string]string{"src/main.rs": actixHead +
			"mod a {\n    #[get(\"/a\")]\n    pub async fn index() -> String { String::new() }\n}\nmod b {\n    #[get(\"/b\")]\n    pub async fn index() -> String { String::new() }\n}\nfn main() { App::new().service(index); }\n"}, nil},
		{"a path held in a constant is not guessed", map[string]string{"src/main.rs": actixHead + "#[get(PATH)]\nasync fn a() -> String { String::new() }\nfn main() { App::new().service(a).route(CONST_PATH, web::get().to(a)); }\n"}, nil},
		{"rocket attribute macros are not actix routes", map[string]string{"src/main.rs": "use rocket::{get, routes};\n#[get(\"/x\")]\nfn x() -> &'static str { \"\" }\nfn main() { rocket::build().mount(\"/\", routes![x]); }\n"}, nil},
		{"service and route on something that is not an actix app", map[string]string{"src/main.rs": actixHead + "fn main() {\n    registry.service(health);\n    router.route(\"/p\", web::get().to(h));\n}\n"}, nil},
		{"a lookalike App and web module of another crate", map[string]string{"src/main.rs": "use mycrate::{App, web};\nfn main() { App::new().route(\"/admin/x\", web::delete().to(h)); }\n"}, nil},
		{"a file with no actix at all", map[string]string{"src/main.rs": "use axum::{routing::get, Router};\nfn main() { let a = Router::new().route(\"/x\", get(h)); }\n"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := routeKeys(a); !slices.Equal(got, c.want) {
				t.Fatalf("routes = %v, want %v", got, c.want)
			}
			for _, r := range a.Routes() {
				if r.Reader != ReaderActix {
					t.Errorf("%s %s read by %q, want %q", r.Method, r.Path, r.Reader, ReaderActix)
				}
			}
		})
	}
}

func TestActixMissingAuthenticationLeads(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"delete with nothing in front", actixApp("App::new().service(del_user)"), []string{"DELETE /users/{id}"}},
		{"admin route on the app", actixApp("App::new().route(\"/admin/stats\", web::get().to(stats))"), []string{"GET /admin/stats"}},
		{"a scope's wrap does not cover its sibling or the app", actixApp("App::new().service(web::scope(\"/safe\").wrap(auth_middleware).service(del_user)).service(web::scope(\"/open\").service(del_user)).route(\"/admin/x\", web::get().to(stats))"),
			[]string{"DELETE /open/users/{id}", "GET /admin/x"}},
		{"logging and compression are not authentication", actixApp("App::new().wrap(Logger::default()).wrap(Compress::default()).service(del_user)"), []string{"DELETE /users/{id}"}},
		{"Option<Identity> does not require a login", map[string]string{"src/main.rs": actixHead + "#[delete(\"/x/{id}\")]\nasync fn d(user: Option<Identity>) -> String { String::new() }\nfn main() { App::new().service(d); }\n"}, []string{"DELETE /x/{id}"}},
		{"a handler named for auth is not middleware", actixApp("App::new().route(\"/admin/revoke\", web::post().to(auth::revoke))"), []string{"POST /admin/revoke"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := authnLeads(a); !slices.Equal(got, c.want) {
				t.Fatalf("leads = %v, want %v (routes %v)", got, c.want, routeKeys(a))
			}
		})
	}
}

func TestActixSafeVariantsAreNotLeads(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"app wrap before", actixApp("App::new().wrap(HttpAuthentication::bearer(validator)).service(del_user)")},
		{"app wrap after covers the services before it", actixApp("App::new().service(del_user).wrap(HttpAuthentication::bearer(validator))")},
		{"scope wrap", actixApp("App::new().service(web::scope(\"/api\").wrap(auth_middleware).service(del_user))")},
		{"scope wrap covers a nested scope", actixApp("App::new().service(web::scope(\"/api\").wrap(JwtAuth).service(web::scope(\"/v1\").service(del_user)))")},
		{"resource wrap", actixApp("App::new().service(web::resource(\"/items/{id}\").wrap(RequireAuth).route(web::delete().to(stats)))")},
		{"attribute wrap argument", map[string]string{"src/main.rs": actixHead + "#[delete(\"/x/{id}\", wrap = \"AuthMiddleware\")]\nasync fn d() -> String { String::new() }\nfn main() { App::new().service(d); }\n"}},
		{"extractor in the handler signature", map[string]string{"src/main.rs": actixHead + "#[delete(\"/x/{id}\")]\nasync fn d(user: AuthenticatedUser, path: web::Path<u32>) -> String { String::new() }\nfn main() { App::new().service(d); }\n"}},
		{"bearer extractor", map[string]string{"src/main.rs": actixHead + "#[delete(\"/x/{id}\")]\nasync fn d(_auth: BearerAuth) -> String { String::new() }\nfn main() { App::new().service(d); }\n"}},
		{"handler answers 401 itself", map[string]string{"src/main.rs": actixHead + "#[delete(\"/x/{id}\")]\nasync fn d(req: HttpRequest) -> HttpResponse {\n    if req.headers().get(\"Authorization\").is_none() { return HttpResponse::Unauthorized().finish(); }\n    HttpResponse::Ok().finish()\n}\nfn main() { App::new().service(d); }\n"}},
		{"configure function reached through an authenticated scope", map[string]string{"src/main.rs": actixHead +
			"fn config(cfg: &mut web::ServiceConfig) {\n    cfg.route(\"/c/{id}\", web::delete().to(h));\n}\n" +
			"fn main() { App::new().service(web::scope(\"/x\").wrap(auth_middleware).configure(config)); }\n"}},
		{"configure function nothing calls is unseen", map[string]string{"src/main.rs": actixHead +
			"pub fn config(cfg: &mut web::ServiceConfig) {\n    cfg.route(\"/c/{id}\", web::delete().to(h));\n}\n"}},
		{"a test directory is not production", map[string]string{"tests/api.rs": actixHead + "fn main() { App::new().route(\"/admin/x\", web::delete().to(h)); }\n"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := authnLeads(a); len(got) != 0 {
				t.Fatalf("leads = %v, want none (routes %v)", got, routeKeys(a))
			}
			if len(a.Routes()) == 0 && c.name != "a test directory is not production" {
				t.Fatal("no route was read, so the case guards nothing")
			}
		})
	}
}
