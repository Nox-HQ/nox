package authz

import (
	"slices"
	"testing"
)

// An application whose API is authenticated by IdentityServer (or any OIDC
// authority) declares its guard in the host: a fallback policy, or
// MapControllers().RequireAuthorization(). Registering IdentityServer or a JWT
// bearer scheme is not a guard by itself, and neither is UseAuthorization().
func TestAspNetIdentityServerGuards(t *testing.T) {
	const orders = csHead + "[ApiController]\n[Route(\"api/[controller]\")]\npublic class OrdersController : ControllerBase\n{\n" +
		"    [HttpPut(\"{id}\")]\n    public IActionResult Put(int id) => Ok();\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}\n"
	const idsrv = "var builder = WebApplication.CreateBuilder(args);\nbuilder.Services.AddControllers();\n" +
		"builder.Services.AddIdentityServer().AddInMemoryClients(clients);\n" +
		"builder.Services.AddAuthentication(\"Bearer\").AddJwtBearer(\"Bearer\", o => { o.Authority = \"https://localhost:5001\"; });\n"
	host := func(authz, endpoints string) string {
		return idsrv + authz + "var app = builder.Build();\napp.UseIdentityServer();\napp.UseAuthentication();\napp.UseAuthorization();\n" + endpoints + "\napp.Run();\n"
	}
	one := func(prog string) map[string]string {
		return map[string]string{"Api/Api.csproj": "<Project />", "Api/Program.cs": prog, "Api/OrdersController.cs": orders}
	}
	split := func(prog string) map[string]string {
		return map[string]string{"Lib/Lib.csproj": "<Project />", "Lib/OrdersController.cs": orders, "Host/Host.csproj": "<Project />", "Host/Program.cs": prog}
	}
	both := []string{"DELETE /api/Orders/{id}", "PUT /api/Orders/{id}"}
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		// The guard is there.
		{"AddFallbackPolicy on the authorization builder", one(host("builder.Services.AddAuthorizationBuilder().AddFallbackPolicy(\"auth\", p => p.RequireAuthenticatedUser());\n", "app.MapControllers();")), nil},
		{"the endpoint convention builder kept in a variable", one(host("", "var endpoints = app.MapControllers();\nendpoints.RequireAuthorization(\"ApiScope\");")), nil},
		{"controllers in a library, the host requires authorization", split(host("", "app.MapControllers().RequireAuthorization(\"ApiScope\");")), nil},
		{"controllers in a library, the host has a fallback policy", split(host("builder.Services.AddAuthorization(o => { o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build(); });\n", "app.MapControllers();")), nil},

		// The guard is not there: each of these still reports.
		{"IdentityServer, a bearer scheme and UseAuthorization only", one(host("", "app.MapControllers();")), both},
		{"a default policy is not a fallback policy", one(host("builder.Services.AddAuthorization(o => { o.DefaultPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build(); });\n", "app.MapControllers();")), both},
		{"AddPolicy and AddDefaultPolicy are not fallback policies", one(host("builder.Services.AddAuthorizationBuilder().AddPolicy(\"p\", x => x.RequireAuthenticatedUser()).AddDefaultPolicy(\"d\", x => x.RequireAuthenticatedUser());\n", "app.MapControllers();")), both},
		{"a fallback policy set to null", one(host("builder.Services.AddAuthorization(o => { o.FallbackPolicy = null; });\n", "app.MapControllers();")), both},
		{"RequireAuthorization on a group variable is not on the controllers", one(host("", "var api = app.MapGroup(\"/other\");\napi.RequireAuthorization();\nvar endpoints = app.MapControllers();")), both},
		{"controllers in a library, the host has no guard", split(host("", "app.MapControllers();")), both},
		{"two hosts, one guarded: the other's own controllers are still reported", map[string]string{
			"Guarded/Guarded.csproj": "<Project />", "Guarded/Program.cs": host("", "app.MapControllers().RequireAuthorization();"),
			"Open/Open.csproj": "<Project />", "Open/Program.cs": host("", "app.MapControllers();"), "Open/OrdersController.cs": orders}, both},
		{"controllers in a library, the only guarded project is not a host", map[string]string{
			"Lib/Lib.csproj": "<Project />", "Lib/OrdersController.cs": orders,
			"Other/Other.csproj": "<Project />", "Other/Policies.cs": "builder.Services.AddAuthorization(o => { o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build(); });\n"}, both},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := authnLeads(a); !slices.Equal(got, c.want) {
				t.Fatalf("leads = %v, want %v (routes %v)", got, c.want, routeKeys(a))
			}
			if len(a.Routes()) == 0 {
				t.Fatalf("no route was read, so the case guards nothing")
			}
		})
	}
}
