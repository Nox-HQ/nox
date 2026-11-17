package authz

import (
	"slices"
	"testing"
)

const pmHead = "using Microsoft.AspNetCore.Authorization;\nusing Microsoft.AspNetCore.Mvc;\nusing Microsoft.AspNetCore.Mvc.RazorPages;\n\nnamespace App.Pages;\n\n"

func merge(ms ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// razorPage is a Pages/<name>.cshtml with its PageModel in <name>.cshtml.cs.
func rzPage(name, directive, model, class string) map[string]string {
	return map[string]string{
		name + ".cshtml":    directive + "\n@model " + model + "\n<h1>x</h1>\n",
		name + ".cshtml.cs": pmHead + class,
	}
}

func pageModel(name, attrs, body string) string {
	return attrs + "public class " + name + " : PageModel\n{\n" + body + "\n}\n"
}

func razorProgram(extra string) map[string]string {
	return map[string]string{"Program.cs": "var builder = WebApplication.CreateBuilder(args);\nbuilder.Services.AddRazorPages(" + extra + ");\nvar app = builder.Build();\napp.MapRazorPages();\napp.Run();\n"}
}

func TestRazorPagesRouteTable(t *testing.T) {
	users := pageModel("UsersModel", "", "    public void OnGet(int? id) { }\n    public async Task<IActionResult> OnPostDeleteAsync(int id) { return RedirectToPage(); }")
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"a rooted template replaces the path", rzPage("Pages/Admin/Users", "@page \"/admin/users/{id?}\"", "UsersModel", users),
			[]string{"GET /admin/users/{id?}", "POST /admin/users/{id?}"}},
		{"the path is the file's under Pages", rzPage("Pages/Admin/Users", "@page", "UsersModel", users),
			[]string{"GET /Admin/Users", "POST /Admin/Users"}},
		{"a relative template is appended", rzPage("Pages/Orders/Details", "@page \"{id:int}\"", "DetailsModel", pageModel("DetailsModel", "", "    public void OnGet(int id) { }")),
			[]string{"GET /Orders/Details/{id:int}"}},
		{"Index is the directory", merge(
			rzPage("Pages/Index", "@page", "IndexModel", pageModel("IndexModel", "", "    public void OnGet() { }")),
			rzPage("Pages/Admin/Index", "@page", "AdminIndexModel", pageModel("AdminIndexModel", "", "    public void OnGet() { }"))),
			[]string{"GET /", "GET /Admin"}},
		{"an area", rzPage("Areas/Billing/Pages/Invoices/Index", "@page", "InvoicesModel", pageModel("InvoicesModel", "", "    public void OnGet() { }")),
			[]string{"GET /Billing/Invoices"}},
		{"a page with only a post handler still answers GET", rzPage("Pages/Contact", "@page", "ContactModel", pageModel("ContactModel", "", "    public IActionResult OnPost() { return Page(); }")),
			[]string{"GET /Contact", "POST /Contact"}},
		{"a page with no model", map[string]string{"Pages/About.cshtml": "@page\n<p>about</p>\n"},
			[]string{"GET /About"}},
		{"every verb handler, sync and async", rzPage("Pages/Things", "@page", "ThingsModel", pageModel("ThingsModel", "",
			"    public void OnGetAsync() { }\n    public void OnPutAsync() { }\n    public void OnDelete() { }\n    public void OnPatchRename() { }")),
			[]string{"DELETE /Things", "GET /Things", "PATCH /Things", "PUT /Things"}},
		// the guards of the reader
		{"a view without @page is not a route", map[string]string{"Pages/Shared/_Layout.cshtml": "<html></html>\n", "Pages/Partial.cshtml": "<p>@Model.X</p>\n"}, nil},
		{"@page in a Razor comment is not a directive", map[string]string{"Pages/Old.cshtml": "@* @page *@\n<p>old</p>\n"}, nil},
		{"@pageTitle is not @page", map[string]string{"Pages/Title.cshtml": "@pageTitle\n<p>t</p>\n"}, nil},
		{"a page outside the Pages root is not routed", map[string]string{"Views/Home/Index.cshtml": "@page\n<p>x</p>\n"}, nil},
		{"private, non-handler and NonHandler methods", rzPage("Pages/Safe", "@page", "SafeModel", pageModel("SafeModel", "",
			"    private void OnPostSecret() { }\n    public void Helper() { }\n    [NonHandler]\n    public void OnPutIgnored() { }\n    public void Onboard() { }")),
			[]string{"GET /Safe"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := routeKeys(a); !slices.Equal(got, c.want) {
				t.Fatalf("routes = %v, want %v", got, c.want)
			}
			for _, r := range a.Routes() {
				if r.Reader != ReaderRazorPages {
					t.Errorf("%s %s read by %q, want %q", r.Method, r.Path, r.Reader, ReaderRazorPages)
				}
			}
		})
	}
}

func TestRazorPagesMissingAuthenticationLeads(t *testing.T) {
	adminPage := func(attrs, body string) map[string]string {
		return rzPage("Pages/Admin/Users", "@page", "UsersModel", pageModel("UsersModel", attrs, body))
	}
	get := "    public void OnGet() { }"
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"an admin page with nothing in front", adminPage("", get), []string{"GET /Admin/Users"}},
		{"a delete handler", rzPage("Pages/Posts/Remove", "@page", "RemoveModel", pageModel("RemoveModel", "", "    public void OnDelete(int id) { }")), []string{"DELETE /Posts/Remove"}},
		{"Authorize on a sibling page", merge(adminPage("", get),
			rzPage("Pages/Admin/Other", "@page", "OtherModel", pageModel("OtherModel", "[Authorize]\n", get))), []string{"GET /Admin/Users"}},
		{"Authorize on a sibling handler", adminPage("", "    [Authorize]\n    public void OnGetStats() { }\n    public void OnGet() { }"), []string{"GET /Admin/Users"}},
		{"a folder convention for another folder", merge(adminPage("", get), razorProgram("o => o.Conventions.AuthorizeFolder(\"/Account\")")), []string{"GET /Admin/Users"}},
		{"a folder convention that only shares a prefix", merge(adminPage("", get), razorProgram("o => o.Conventions.AuthorizeFolder(\"/Adm\")")), []string{"GET /Admin/Users"}},
		{"a convention in a comment", merge(adminPage("", get), map[string]string{"Program.cs": "// options.Conventions.AuthorizeFolder(\"/Admin\");\nvar app = WebApplication.Create(args);\napp.MapRazorPages();\n"}), []string{"GET /Admin/Users"}},
		{"a page convention for another page", merge(adminPage("", get), razorProgram("o => o.Conventions.AuthorizePage(\"/Admin/Other\")")), []string{"GET /Admin/Users"}},
		{"UseAuthentication alone authenticates nothing", merge(adminPage("", get), map[string]string{"Program.cs": "var app = WebApplication.Create(args);\napp.UseAuthentication();\napp.UseAuthorization();\napp.MapRazorPages();\n"}), []string{"GET /Admin/Users"}},
		{"an attribute that does not derive from Authorize", merge(adminPage("[Logged]\n", get), map[string]string{"Logged.cs": "public class LoggedAttribute : Attribute {}\n"}), []string{"GET /Admin/Users"}},
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

func TestRazorPagesSafeVariantsAreNotLeads(t *testing.T) {
	get := "    public void OnGet() { }"
	admin := func(attrs, body string) map[string]string {
		return rzPage("Pages/Admin/Users", "@page", "UsersModel", pageModel("UsersModel", attrs, body))
	}
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"Authorize on the model", admin("[Authorize]\n", get)},
		{"Authorize with a policy", admin("[Authorize(Policy = \"Admins\")]\n", get)},
		{"Authorize on the handler", admin("", "    [Authorize]\n    public void OnGet() { }")},
		{"AllowAnonymous", admin("[AllowAnonymous]\n", get)},
		{"Authorize on a base model of the project", merge(
			map[string]string{"Pages/AuthPageModel.cs": pmHead + "[Authorize]\npublic class AuthPageModel : PageModel {}\n"},
			rzPage("Pages/Admin/Users", "@page", "UsersModel", "public class UsersModel : AuthPageModel\n{\n    public void OnGet() { }\n}\n"))},
		{"@attribute [Authorize] in the page", map[string]string{
			"Pages/Admin/Users.cshtml": "@page\n@attribute [Authorize]\n@model UsersModel\n", "Pages/Admin/Users.cshtml.cs": pmHead + pageModel("UsersModel", "", get)}},
		{"AuthorizeFolder", merge(admin("", get), razorProgram("o => o.Conventions.AuthorizeFolder(\"/Admin\")"))},
		{"AuthorizeFolder on the root", merge(admin("", get), razorProgram("o => o.Conventions.AuthorizeFolder(\"/\")"))},
		{"AuthorizePage", merge(admin("", get), razorProgram("o => o.Conventions.AuthorizePage(\"/Admin/Users\")"))},
		{"AuthorizeAreaFolder", merge(rzPage("Areas/Billing/Pages/Invoices/Index", "@page", "InvoicesModel", pageModel("InvoicesModel", "", get)),
			map[string]string{"Program.cs": "builder.Services.AddRazorPages(o => o.Conventions.AuthorizeAreaFolder(\"Billing\", \"/Invoices\"));\n"})},
		{"AllowAnonymousToPage makes the page public by intent", merge(admin("", get), razorProgram("o => o.Conventions.AllowAnonymousToPage(\"/Admin/Users\")"))},
		{"MapRazorPages().RequireAuthorization() is project-wide and unseen", merge(admin("", get), map[string]string{"Program.cs": "var app = WebApplication.Create(args);\napp.MapRazorPages().RequireAuthorization();\n"})},
		{"a fallback policy is project-wide and unseen", merge(admin("", get), map[string]string{"Program.cs": "builder.Services.AddAuthorization(o => { o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build(); });\n"})},
		{"the handler reads the caller", admin("", "    public IActionResult OnGet() { if (!User.Identity.IsAuthenticated) return Forbid(); return Page(); }")},
		{"a base model outside the tree is unseen", rzPage("Pages/Admin/Users", "@page", "UsersModel", "public class UsersModel : ThirdPartyPageModel\n{\n    public void OnGet() { }\n}\n")},
		{"a model the project does not declare is unseen", map[string]string{"Pages/Admin/Users.cshtml": "@page\n@model Missing.UsersModel\n"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := authnLeads(a); len(got) != 0 {
				t.Fatalf("leads = %v, want none (routes %v)", got, routeKeys(a))
			}
			if len(a.Routes()) == 0 {
				t.Fatal("no route was read, so the case guards nothing")
			}
		})
	}
}

// ---- conventional MVC routing ----

const mvcHead = "using Microsoft.AspNetCore.Authorization;\nusing Microsoft.AspNetCore.Mvc;\n\nnamespace App.Controllers;\n\n"

func mvcCtl(file, body string) map[string]string {
	return map[string]string{"Controllers/" + file + ".cs": mvcHead + body}
}

func mvcProgram(body string) map[string]string {
	return map[string]string{"Program.cs": "var builder = WebApplication.CreateBuilder(args);\nbuilder.Services.AddControllersWithViews();\nvar app = builder.Build();\n" + body + "\napp.Run();\n"}
}

const defaultRoute = "app.MapControllerRoute(name: \"default\", pattern: \"{controller=Home}/{action=Index}/{id?}\");"

func TestAspNetConventionalRouteTable(t *testing.T) {
	users := mvcCtl("UsersController", `public class UsersController : Controller
{
    public IActionResult Index() => View();

    [HttpPost]
    public IActionResult Delete(int id) => RedirectToAction("Index");

    [HttpGet("export")]
    public IActionResult Export() => View();

    [NonAction]
    public void Helper() {}

    private IActionResult Secret() => View();

    public static string Util() => "";

    protected IActionResult Prot() => View();

    public override void OnActionExecuting(ActionExecutingContext c) {}
}`)
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"the default pattern over public actions", merge(users, mvcProgram(defaultRoute)),
			[]string{"ALL /Users/Index/{id?}", "GET /export", "POST /Users/Delete/{id?}"}},
		{"MapDefaultControllerRoute", merge(users, mvcProgram("app.MapDefaultControllerRoute();")),
			[]string{"ALL /Users/Index/{id?}", "GET /export", "POST /Users/Delete/{id?}"}},
		{"a pattern with a literal prefix and positional arguments", merge(users, mvcProgram("app.MapControllerRoute(\"api\", \"api/{controller}/{action}\");")),
			[]string{"ALL /api/Users/Index", "GET /export", "POST /api/Users/Delete"}},
		{"UseMvc with MapRoute", merge(users, map[string]string{"Startup.cs": "public class Startup { public void Configure(IApplicationBuilder app) { app.UseMvc(routes => { routes.MapRoute(\"default\", \"{controller=Home}/{action=Index}/{id?}\"); }); } }\n"}),
			[]string{"ALL /Users/Index/{id?}", "GET /export", "POST /Users/Delete/{id?}"}},
		{"UseMvcWithDefaultRoute", merge(users, map[string]string{"Startup.cs": "public class Startup { public void Configure(IApplicationBuilder app) { app.UseMvcWithDefaultRoute(); } }\n"}),
			[]string{"ALL /Users/Index/{id?}", "GET /export", "POST /Users/Delete/{id?}"}},
		{"an area controller takes the area pattern only", merge(
			mvcCtl("ReportsController", "[Area(\"Admin\")]\npublic class ReportsController : Controller\n{\n    public IActionResult List() => View();\n}"),
			mvcCtl("HomeController", "public class HomeController : Controller\n{\n    public IActionResult Index() => View();\n}"),
			mvcProgram("app.MapControllerRoute(name: \"areas\", pattern: \"{area:exists}/{controller=Home}/{action=Index}/{id?}\");\n"+defaultRoute)),
			[]string{"ALL /Admin/Reports/List/{id?}", "ALL /Home/Index/{id?}"}},
		{"MapAreaControllerRoute", merge(
			mvcCtl("ReportsController", "[Area(\"Admin\")]\npublic class ReportsController : Controller\n{\n    public IActionResult List() => View();\n}"),
			mvcProgram("app.MapAreaControllerRoute(name: \"admin\", areaName: \"Admin\", pattern: \"Admin/{controller}/{action}\");")),
			[]string{"ALL /Admin/Reports/List"}},
		{"an area route is not for another area's controller", merge(
			mvcCtl("ReportsController", "[Area(\"Other\")]\npublic class ReportsController : Controller\n{\n    public IActionResult List() => View();\n}"),
			mvcProgram("app.MapAreaControllerRoute(name: \"admin\", areaName: \"Admin\", pattern: \"Admin/{controller}/{action}\");")), nil},
		// the guards of the reader
		{"without a conventional route there is none to read", merge(users, mvcProgram("app.MapControllers();")), []string{"GET /export"}},
		{"a class-level Route makes every action attribute-routed", merge(mvcCtl("ThingsController", "[Route(\"things\")]\npublic class ThingsController : Controller\n{\n    public IActionResult Index() => View();\n}"), mvcProgram(defaultRoute)), nil},
		{"an ApiController is attribute-routed", merge(mvcCtl("ThingsController", "[ApiController]\npublic class ThingsController : ControllerBase\n{\n    public IActionResult Index() => Ok();\n}"), mvcProgram(defaultRoute)), nil},
		{"a service class is not a controller", merge(mvcCtl("UserService", "public class UserService\n{\n    public void Delete(int id) {}\n}"), mvcProgram(defaultRoute)), nil},
		{"an internal controller is not discovered", merge(mvcCtl("HiddenController", "internal class HiddenController : Controller\n{\n    public IActionResult Index() => View();\n}"), mvcProgram(defaultRoute)), nil},
		{"an abstract controller is not discovered", merge(mvcCtl("BaseController", "public abstract class BaseController : Controller\n{\n    public IActionResult Index() => View();\n}"), mvcProgram(defaultRoute)), nil},
		{"a pattern held in a constant is not guessed", merge(users, mvcProgram("app.MapControllerRoute(name: \"d\", pattern: Routes.Default);")), []string{"GET /export"}},
		{"a pattern in a comment", merge(users, map[string]string{"Program.cs": "var app = WebApplication.Create(args);\n// app.MapDefaultControllerRoute();\napp.MapControllers();\n"}), []string{"GET /export"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := routeKeys(a); !slices.Equal(got, c.want) {
				t.Fatalf("routes = %v, want %v", got, c.want)
			}
			for _, r := range a.Routes() {
				want := ReaderAspNetMVC
				if r.Path == "/export" {
					want = ReaderASPNET
				}
				if r.Reader != want {
					t.Errorf("%s %s read by %q, want %q", r.Method, r.Path, r.Reader, want)
				}
			}
		})
	}
}

func TestAspNetConventionalMissingAuthenticationLeads(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"a delete action with nothing in front", merge(mvcCtl("UsersController", "public class UsersController : Controller\n{\n    [HttpDelete]\n    public IActionResult Remove(int id) => Ok();\n}"), mvcProgram(defaultRoute)),
			[]string{"DELETE /Users/Remove/{id?}"}},
		{"an admin controller", merge(mvcCtl("AdminController", "public class AdminController : Controller\n{\n    public IActionResult Dashboard() => View();\n}"), mvcProgram(defaultRoute)),
			[]string{"ALL /Admin/Dashboard/{id?}"}},
		{"Authorize on a sibling controller", merge(
			mvcCtl("AController", "[Authorize]\npublic class AController : Controller\n{\n    [HttpDelete]\n    public IActionResult Remove() => Ok();\n}"),
			mvcCtl("BController", "public class BController : Controller\n{\n    [HttpDelete]\n    public IActionResult Remove() => Ok();\n}"), mvcProgram(defaultRoute)),
			[]string{"DELETE /B/Remove/{id?}"}},
		{"Authorize on a sibling action", mergeOne(mvcCtl("UsersController", "public class UsersController : Controller\n{\n    [Authorize]\n    [HttpDelete]\n    public IActionResult A() => Ok();\n\n    [HttpDelete]\n    public IActionResult B() => Ok();\n}"), mvcProgram(defaultRoute)),
			[]string{"DELETE /Users/B/{id?}"}},
		{"UseAuthentication alone authenticates nothing", merge(mvcCtl("UsersController", "public class UsersController : Controller\n{\n    [HttpDelete]\n    public IActionResult Remove() => Ok();\n}"),
			mvcProgram("app.UseAuthentication();\napp.UseAuthorization();\n"+defaultRoute)), []string{"DELETE /Users/Remove/{id?}"}},
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

func mergeOne(a, b map[string]string) map[string]string { return merge(a, b) }

func TestAspNetConventionalSafeVariantsAreNotLeads(t *testing.T) {
	del := func(attrs, member string) map[string]string {
		return merge(mvcCtl("UsersController", attrs+"public class UsersController : Controller\n{\n"+member+"    [HttpDelete]\n    public IActionResult Remove() => Ok();\n}"), mvcProgram(defaultRoute))
	}
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"Authorize on the controller", del("[Authorize]\n", "")},
		{"Authorize with roles", del("[Authorize(Roles = \"Admin\")]\n", "")},
		{"Authorize on the action", merge(mvcCtl("UsersController", "public class UsersController : Controller\n{\n    [Authorize]\n    [HttpDelete]\n    public IActionResult Remove() => Ok();\n}"), mvcProgram(defaultRoute))},
		{"Authorize on a base controller of the project", merge(
			mvcCtl("SecureController", "[Authorize]\npublic abstract class SecureController : Controller {}\n"),
			mvcCtl("UsersController", "public class UsersController : SecureController\n{\n    [HttpDelete]\n    public IActionResult Remove() => Ok();\n}"), mvcProgram(defaultRoute))},
		{"AllowAnonymous is public by intent", del("[AllowAnonymous]\n", "")},
		{"a fallback policy is project-wide and unseen", merge(del("", ""), map[string]string{"Policies.cs": "builder.Services.AddAuthorization(o => { o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build(); });\n"})},
		{"a global AuthorizeFilter is unseen", merge(del("", ""), map[string]string{"Filters.cs": "builder.Services.AddControllersWithViews(o => o.Filters.Add(new AuthorizeFilter()));\n"})},
		{"a base controller outside the tree is unseen", merge(mvcCtl("UsersController", "public class UsersController : ThirdPartyController\n{\n    [HttpDelete]\n    public IActionResult Remove() => Ok();\n}"), mvcProgram(defaultRoute))},
		{"the action reads the caller", merge(mvcCtl("UsersController", "public class UsersController : Controller\n{\n    [HttpDelete]\n    public IActionResult Remove() { if (!User.Identity.IsAuthenticated) return Forbid(); return Ok(); }\n}"), mvcProgram(defaultRoute))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := authnLeads(a); len(got) != 0 {
				t.Fatalf("leads = %v, want none (routes %v)", got, routeKeys(a))
			}
			if len(a.Routes()) == 0 {
				t.Fatal("no route was read, so the case guards nothing")
			}
		})
	}
}
