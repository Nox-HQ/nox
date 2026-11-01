package authz

import (
	"slices"
	"testing"
)

const csHead = "using Microsoft.AspNetCore.Authorization;\nusing Microsoft.AspNetCore.Mvc;\n\nnamespace App.Controllers;\n\n"

func csCtl(body string) map[string]string {
	return map[string]string{"Api/Controllers/UsersController.cs": csHead + body}
}

func csProgram(body string) map[string]string {
	return map[string]string{"Api/Program.cs": "var builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\n" + body + "\napp.Run();\n"}
}

func TestAspNetControllerRouteTable(t *testing.T) {
	files := csCtl(`[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    [HttpGet]
    public IActionResult List() => Ok();

    [HttpGet("{id:int}")]
    public IActionResult Get(int id) => Ok();

    [HttpPost]
    public IActionResult Create() => Ok();

    [HttpDelete("{id}")]
    [HttpPut("{id}")]
    public IActionResult Change(int id) => Ok();

    [HttpGet("~/health")]
    public IActionResult Health() => Ok();

    [Route("[action]")]
    public IActionResult Export() => Ok();

    [NonAction]
    public void Helper() {}

    [HttpGet(Constants.Route)]
    public IActionResult Const() => Ok();
}`)
	a, _ := scanFiles(t, files)
	want := []string{"ALL /api/Users/Export", "DELETE /api/Users/{id}", "GET /api/Users", "GET /api/Users/{id:int}", "GET /health", "POST /api/Users", "PUT /api/Users/{id}"}
	if got := routeKeys(a); !slices.Equal(got, want) {
		t.Fatalf("routes = %v\nwant     %v", got, want)
	}
}

func TestAspNetControllerLeads(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"delete with no attribute", csCtl("[ApiController]\n[Route(\"api/[controller]\")]\npublic class UsersController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}"), []string{"DELETE /api/Users/{id}"}},
		{"Authorize on a sibling method", csCtl("[Route(\"api/[controller]\")]\npublic class UsersController : ControllerBase\n{\n    [Authorize]\n    [HttpGet(\"{id}\")]\n    public IActionResult Get(int id) => Ok();\n\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}"), []string{"DELETE /api/Users/{id}"}},
		{"Authorize on another controller", map[string]string{
			"A.cs": csHead + "[Authorize]\n[Route(\"a\")]\npublic class AController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult D(int id) => Ok();\n}",
			"B.cs": csHead + "[Route(\"b\")]\npublic class BController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult D(int id) => Ok();\n}"}, []string{"DELETE /b/{id}"}},
		{"UseAuthentication and UseAuthorization alone authenticate nothing", map[string]string{
			"Api/Program.cs":         "var builder = WebApplication.CreateBuilder(args);\nbuilder.Services.AddAuthentication().AddJwtBearer();\nbuilder.Services.AddAuthorization();\nbuilder.Services.AddControllers();\nvar app = builder.Build();\napp.UseAuthentication();\napp.UseAuthorization();\napp.MapControllers();\napp.Run();\n",
			"Api/UsersController.cs": csHead + "[Route(\"users\")]\npublic class UsersController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult D(int id) => Ok();\n}"}, []string{"DELETE /users/{id}"}},
		{"a fallback policy in another project does not cover this one", map[string]string{
			"Other/Program.cs":       "builder.Services.AddAuthorization(o => { o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build(); });\n",
			"Other/Other.csproj":     "<Project />",
			"Api/Api.csproj":         "<Project />",
			"Api/UsersController.cs": csHead + "[Route(\"users\")]\npublic class UsersController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult D(int id) => Ok();\n}"}, []string{"DELETE /users/{id}"}},
		{"Authorize on a base class in another place does not cover a sibling base", map[string]string{
			"Api/Base.cs": csHead + "[Authorize]\npublic class SecureBase : ControllerBase {}\npublic class OpenBase : ControllerBase {}\n",
			"Api/U.cs":    csHead + "[Route(\"u\")]\npublic class UController : OpenBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult D(int id) => Ok();\n}"}, []string{"DELETE /u/{id}"}},
		{"a comment mentioning Authorize is not an attribute", csCtl("[Route(\"u\")]\npublic class UController : ControllerBase\n{\n    // [Authorize]\n    [HttpDelete(\"{id}\")]\n    public IActionResult D(int id) => Ok();\n}"), []string{"DELETE /u/{id}"}},
		{"minimal api delete", csProgram("app.MapDelete(\"/users/{id}\", (int id) => Results.Ok());"), []string{"DELETE /users/{id}"}},
		{"minimal api in a group", csProgram("var api = app.MapGroup(\"/api\");\nvar v1 = api.MapGroup(\"v1\");\nv1.MapPut(\"/orders/{id}\", () => Results.Ok());"), []string{"PUT /api/v1/orders/{id}"}},
		{"RequireAuthorization on a sibling endpoint", csProgram("app.MapGet(\"/admin/a\", () => 1).RequireAuthorization();\napp.MapGet(\"/admin/b\", () => 2);"), []string{"GET /admin/b"}},
		{"RequireAuthorization on a sibling group", csProgram("var safe = app.MapGroup(\"/safe\").RequireAuthorization();\nvar open = app.MapGroup(\"/open\");\nsafe.MapDelete(\"/x/{id}\", () => 1);\nopen.MapDelete(\"/y/{id}\", () => 1);"), []string{"DELETE /open/y/{id}"}},
		{"extension method fed an unauthenticated group", map[string]string{
			"Api/Program.cs": "var app = WebApplication.Create(args);\napp.MapGroup(\"/api/orders\").MapOrders();\n",
			"Api/Orders.cs":  "public static class OrdersApi\n{\n    public static RouteGroupBuilder MapOrders(this RouteGroupBuilder group)\n    {\n        group.MapDelete(\"/{id}\", (int id) => Results.Ok());\n        return group;\n    }\n}\n"}, []string{"DELETE /api/orders/{id}"}},
		{"UseMiddleware of something not named for authentication", csProgram("app.UseMiddleware<RequestLoggingMiddleware>();\napp.MapDelete(\"/users/{id}\", () => 1);"), []string{"DELETE /users/{id}"}},
		{"a convention on an endpoint whose path is a constant is not carried to the previous endpoint", csProgram("app.MapDelete(\"/users/{id}\", () => 1);\napp.MapDelete(Routes.Admin, () => 1).RequireAuthorization();"), []string{"DELETE /users/{id}"}},
		{"a convention is a group's, never the application's", csProgram("var versioned = app.NewVersionedApi(\"x\");\nversioned.RequireAuthorization();\napp.MapDelete(\"/users/{id}\", () => 1);"), []string{"DELETE /users/{id}"}},
		{"NoPermissionRequired is not a permission check", csCtl("[Route(\"u\")]\npublic class UController : ControllerBase\n{\n    [NoPermissionRequired]\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}"), []string{"DELETE /u/{id}"}},
		{"an attribute that does not derive from Authorize", map[string]string{"Api/U.cs": csHead + "public class LoggedAttribute : Attribute {}\n[Route(\"u\")]\npublic class UController : ControllerBase\n{\n    [Logged]\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}"}, []string{"DELETE /u/{id}"}},
		{"AllowAnonymous elsewhere does not matter", csProgram("app.MapGet(\"/public\", () => 1).AllowAnonymous();\napp.MapDelete(\"/users/{id}\", () => 1);"), []string{"DELETE /users/{id}"}},
		{"Startup UseEndpoints", map[string]string{"Api/Startup.cs": "using Microsoft.AspNetCore.Builder;\npublic class Startup\n{\n    public void Configure(IApplicationBuilder app)\n    {\n        app.UseEndpoints(endpoints =>\n        {\n            endpoints.MapDelete(\"/users/{id}\", ctx => ctx.Response.WriteAsync(\"x\"));\n        });\n    }\n}\n"}, []string{"DELETE /users/{id}"}},
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

func TestAspNetSafeVariantsAreNotLeads(t *testing.T) {
	ctl := func(attrs, method string) map[string]string {
		return csCtl(attrs + "\n[Route(\"api/[controller]\")]\npublic class UsersController : ControllerBase\n{\n" + method + "\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}")
	}
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"Authorize on the class", ctl("[Authorize]", "")},
		{"Authorize with roles", ctl("[Authorize(Roles = \"Admin\")]", "")},
		{"Authorize with policy", ctl("[Authorize(Policy = \"CanDelete\")]", "")},
		{"Authorize on the method", csCtl("[Route(\"u\")]\npublic class UController : ControllerBase\n{\n    [Authorize]\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}")},
		{"Authorize in the same list", csCtl("[Route(\"u\")]\npublic class UController : ControllerBase\n{\n    [HttpDelete(\"{id}\"), Authorize]\n    public IActionResult Delete(int id) => Ok();\n}")},
		{"fully qualified Authorize", csCtl("[Route(\"u\")]\n[Microsoft.AspNetCore.Authorization.Authorize]\npublic class UController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}")},
		{"AuthorizeAttribute spelled out", csCtl("[Route(\"u\")]\n[AuthorizeAttribute]\npublic class UController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}")},
		{"custom authentication attribute", csCtl("[Route(\"u\")]\n[JwtAuthorize]\npublic class UController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}")},
		{"an attribute of the project that derives from Authorize", map[string]string{"Api/U.cs": csHead + "public class ZedAttribute : AuthorizeAttribute { public ZedAttribute(string p) {} }\n[Route(\"u\")]\npublic class UController : ControllerBase\n{\n    [Zed(\"x\")]\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}"}},
		{"an attribute deriving from one that derives from Authorize", map[string]string{"Api/U.cs": csHead + "public class BaseZedAttribute : AuthorizeAttribute {}\npublic class YarnAttribute : BaseZedAttribute {}\n[Route(\"u\")]\n[Yarn]\npublic class UController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}"}},
		{"authorization filter by type", csCtl("[Route(\"u\")]\n[ServiceFilter(typeof(ApiKeyAuthFilter))]\npublic class UController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}")},
		{"Authorize on a base class", map[string]string{"Api/B.cs": csHead + "[Authorize]\npublic abstract class SecureController : ControllerBase {}\n[Route(\"u\")]\npublic class UController : SecureController\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}"}},
		{"AllowAnonymous on the method is public on purpose", csCtl("[Route(\"u\")]\npublic class UController : ControllerBase\n{\n    [AllowAnonymous]\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}")},
		{"AllowAnonymous on the class", csCtl("[Route(\"u\")]\n[AllowAnonymous]\npublic class UController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}")},
		{"AllowAnonymous beats Authorize", csCtl("[Route(\"u\")]\n[Authorize]\npublic class UController : ControllerBase\n{\n    [AllowAnonymous]\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}")},
		{"the handler reads the caller", csCtl("[Route(\"u\")]\npublic class UController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id)\n    {\n        if (!User.Identity.IsAuthenticated) return Unauthorized();\n        return Ok();\n    }\n}")},
		{"a base class outside the project is unseen", csCtl("[Route(\"u\")]\npublic class UController : CompanyApiBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}")},
		{"fallback policy", map[string]string{"Api/Program.cs": "builder.Services.AddAuthorization(o => { o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build(); });\n", "Api/U.cs": csHead + "[Route(\"u\")]\npublic class UController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}"}},
		{"fallback policy builder", map[string]string{"Api/Program.cs": "var app = WebApplication.Create(args);\nbuilder.Services.AddAuthorizationBuilder().SetFallbackPolicy(policy);\napp.MapDelete(\"/users/{id}\", () => 1);\n"}},
		{"global AuthorizeFilter", map[string]string{"Api/Startup.cs": "services.AddControllers(o => o.Filters.Add(new AuthorizeFilter()));\n", "Api/U.cs": csHead + "[Route(\"u\")]\npublic class UController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}"}},
		{"MapControllers().RequireAuthorization()", map[string]string{"Api/Program.cs": "var app = WebApplication.Create(args);\napp.MapControllers().RequireAuthorization();\n", "Api/U.cs": csHead + "[Route(\"u\")]\npublic class UController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}"}},
		{"authentication middleware", map[string]string{"Api/Program.cs": "var app = WebApplication.Create(args);\napp.UseMiddleware<ApiKeyAuthenticationMiddleware>();\napp.MapDelete(\"/users/{id}\", () => 1);\n"}},
		{"minimal: endpoint RequireAuthorization", csProgram("app.MapDelete(\"/users/{id}\", () => 1).RequireAuthorization();")},
		{"minimal: endpoint with policy and name", csProgram("app.MapDelete(\"/users/{id}\", () => 1).WithName(\"x\").RequireAuthorization(\"Admin\").WithTags(\"t\");")},
		{"minimal: group RequireAuthorization", csProgram("var g = app.MapGroup(\"/api\").RequireAuthorization();\ng.MapDelete(\"/users/{id}\", () => 1);")},
		{"minimal: group RequireAuthorization applied after the endpoint", csProgram("var g = app.MapGroup(\"/api\");\ng.MapDelete(\"/users/{id}\", () => 1);\ng.RequireAuthorization();")},
		{"minimal: nested group under an authorized group", csProgram("var g = app.MapGroup(\"/api\").RequireAuthorization();\nvar h = g.MapGroup(\"/v1\");\nh.MapDelete(\"/users/{id}\", () => 1);")},
		{"minimal: Authorize on the lambda", csProgram("app.MapDelete(\"/users/{id}\", [Authorize] (int id) => 1);")},
		{"minimal: AllowAnonymous", csProgram("app.MapDelete(\"/users/{id}\", () => 1).AllowAnonymous();")},
		{"minimal: AllowAnonymous on the group", csProgram("var g = app.MapGroup(\"/api\").AllowAnonymous();\ng.MapDelete(\"/users/{id}\", () => 1);")},
		{"minimal: the handler takes the principal", csProgram("app.MapDelete(\"/users/{id}\", (int id, ClaimsPrincipal user) => 1);")},
		{"minimal: method group with Authorize", map[string]string{"Api/Program.cs": "var app = WebApplication.Create(args);\napp.MapDelete(\"/users/{id}\", Handlers.Remove);\n", "Api/H.cs": "public static class Handlers\n{\n    [Authorize]\n    public static IResult Remove(int id) => Results.Ok();\n}\n"}},
		{"minimal: extension with an authorized group", map[string]string{
			"Api/Program.cs": "var app = WebApplication.Create(args);\napp.MapGroup(\"/api/orders\").RequireAuthorization().MapOrders();\n",
			"Api/Orders.cs":  "public static class OrdersApi\n{\n    public static RouteGroupBuilder MapOrders(this RouteGroupBuilder group)\n    {\n        group.MapDelete(\"/{id}\", (int id) => Results.Ok());\n        return group;\n    }\n}\n"}},
		{"minimal: extension on the builder with its own group", map[string]string{
			"Api/Program.cs": "var app = WebApplication.Create(args);\napp.MapOrders();\n",
			"Api/Orders.cs":  "public static class OrdersApi\n{\n    public static IEndpointRouteBuilder MapOrders(this IEndpointRouteBuilder app)\n    {\n        var api = app.MapGroup(\"/api/orders\").RequireAuthorization();\n        api.MapDelete(\"/{id}\", (int id) => Results.Ok());\n        return app;\n    }\n}\n"}},
		{"minimal: a builder never bound is unseen", map[string]string{"Api/Orders.cs": "public static class OrdersApi\n{\n    public static void MapOrders(this IEndpointRouteBuilder app)\n    {\n        app.MapDelete(\"/orders/{id}\", (int id) => Results.Ok());\n    }\n}\n"}},
		{"test projects are not read", map[string]string{"Api.Tests/UsersControllerTests.cs": csHead + "[Route(\"u\")]\npublic class UController : ControllerBase\n{\n    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) => Ok();\n}"}},
	}
	for _, c := range cases {
		name, files := c.name, c.files
		t.Run(name, func(t *testing.T) {
			a, _ := scanFiles(t, files)
			if got := authnLeads(a); len(got) != 0 {
				t.Fatalf("leads = %v, want none (routes %v)", got, routeKeys(a))
			}
			// A case that proves nothing when the route was never read.
			if len(a.Routes()) == 0 && name != "test projects are not read" {
				t.Fatalf("no route was read, so the case guards nothing")
			}
		})
	}
}

func TestAspNetRoutesNameTheirAuthentication(t *testing.T) {
	a, _ := scanFiles(t, csProgram("app.MapGet(\"/open\", () => 1);\nvar g = app.MapGroup(\"/api\").RequireAuthorization();\ng.MapDelete(\"/users/{id}\", () => 1);"))
	got := map[string]string{}
	for _, r := range a.Routes() {
		got[r.Method+" "+r.Path] = r.Authn
		if r.Reader != ReaderASPNET {
			t.Errorf("%s read by %q", r.Path, r.Reader)
		}
	}
	if got["GET /open"] != "" || got["DELETE /api/users/{id}"] == "" {
		t.Fatalf("authentication = %v", got)
	}
}

// Visual Studio writes a byte-order mark; the first statement must still be read.
func TestAspNetByteOrderMark(t *testing.T) {
	files := map[string]string{"Api/Program.cs": "\xef\xbb\xbfvar builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\napp.MapDelete(\"/users/{id}\", () => 1);\n"}
	a, _ := scanFiles(t, files)
	if got := authnLeads(a); !slices.Equal(got, []string{"DELETE /users/{id}"}) {
		t.Fatalf("leads = %v (routes %v)", got, routeKeys(a))
	}
}
