package authz

import (
	"slices"
	"testing"
)

const phpHead = "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\nuse App\\Http\\Controllers\\UserController;\nuse App\\Http\\Controllers\\Api\\PostController;\n\n"

func webApp(routes string, extra map[string]string) map[string]string {
	files := map[string]string{"routes/web.php": phpHead + routes}
	for k, v := range extra {
		files[k] = v
	}
	return files
}

func phpController(class, extends, body string) string {
	return "<?php\n\nnamespace App\\Http\\Controllers;\n\nuse App\\Http\\Controllers\\Controller;\n\nclass " + class + " extends " + extends + "\n{\n" + body + "}\n"
}

const (
	phpDestroy = "    public function destroy($id)\n    {\n        User::destroy($id);\n    }\n"
	baseCtl    = "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Routing\\Controller as BaseController;\nclass Controller extends BaseController\n{\n}\n"
)

func userCtl(body string) map[string]string { return userCtlRaw(body + phpDestroy) }

func userCtlRaw(body string) map[string]string {
	return map[string]string{
		"app/Http/Controllers/Controller.php":     baseCtl,
		"app/Http/Controllers/UserController.php": phpController("UserController", "Controller", body),
	}
}

func TestLaravelRouteTable(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"verbs", webApp("Route::get('/users/{id}', [UserController::class, 'show']);\nRoute::post('/users', 'UserController@store');\nRoute::put('/users/{id}', [UserController::class, 'update']);\nRoute::patch('users/{id}', [UserController::class, 'update']);\nRoute::delete('/users/{id}', [UserController::class, 'destroy']);\n", nil),
			[]string{"DELETE /users/{id}", "GET /users/{id}", "PATCH /users/{id}", "POST /users", "PUT /users/{id}"}},
		{"api.php is prefixed", map[string]string{"routes/api.php": phpHead + "Route::delete('/users/{id}', [UserController::class, 'destroy']);\n"},
			[]string{"DELETE /api/users/{id}"}},
		{"any and match", webApp("Route::any('/hook', [UserController::class, 'hook']);\nRoute::match(['get', 'post'], '/sync', [UserController::class, 'sync']);\n", nil),
			[]string{"ALL /hook", "GET /sync", "POST /sync"}},
		{"resource", webApp("Route::resource('photos', PhotoController::class);\n", nil),
			[]string{"DELETE /photos/{photo}", "GET /photos", "GET /photos/create", "GET /photos/{photo}", "GET /photos/{photo}/edit", "PATCH /photos/{photo}", "POST /photos", "PUT /photos/{photo}"}},
		{"apiResource only and except", webApp("Route::apiResource('posts', PostController::class)->only(['index', 'show']);\nRoute::apiResource('tags', PostController::class)->except(['destroy']);\n", nil),
			[]string{"GET /posts", "GET /posts/{post}", "GET /tags", "GET /tags/{tag}", "PATCH /tags/{tag}", "POST /tags", "PUT /tags/{tag}"}},
		{"nested resource", webApp("Route::apiResource('posts.comments', CommentController::class)->only(['destroy']);\n", nil),
			[]string{"DELETE /posts/{post}/comments/{comment}"}},
		{"resources array", webApp("Route::apiResources([\n    'posts' => PostController::class,\n]);\n", nil),
			[]string{"DELETE /posts/{post}", "GET /posts", "GET /posts/{post}", "PATCH /posts/{post}", "POST /posts", "PUT /posts/{post}"}},
		{"prefix groups nest", webApp("Route::prefix('admin')->group(function () {\n    Route::prefix('v1')->group(function () {\n        Route::delete('/users/{id}', [UserController::class, 'destroy']);\n    });\n    Route::get('/stats', [UserController::class, 'stats']);\n});\n", nil),
			[]string{"DELETE /admin/v1/users/{id}", "GET /admin/stats"}},
		{"array group", webApp("Route::group(['prefix' => 'admin', 'middleware' => 'web'], function () {\n    Route::get('/stats', [UserController::class, 'stats']);\n});\n", nil),
			[]string{"GET /admin/stats"}},
		{"controller group", webApp("Route::controller(UserController::class)->group(function () {\n    Route::get('/users', 'index');\n    Route::delete('/users/{id}', 'destroy');\n});\n", nil),
			[]string{"DELETE /users/{id}", "GET /users"}},
		{"view redirect and fallback are not handlers", webApp("Route::view('/welcome', 'welcome');\nRoute::redirect('/a', '/b');\nRoute::fallback(function () { return 1; });\nRoute::get('/ok', [UserController::class, 'ok']);\n", nil),
			[]string{"GET /ok"}},
		{"closures", webApp("Route::get('/x', function () {\n    return 'x';\n});\nRoute::get('/y', fn () => 'y');\n", nil),
			[]string{"GET /x", "GET /y"}},
		{"a path built from a variable is not guessed", webApp("Route::get($path, [UserController::class, 'a']);\nRoute::get('/a/' . $x, [UserController::class, 'b']);\nRoute::get('/ok', [UserController::class, 'c']);\n", nil),
			[]string{"GET /ok"}},
		{"comments and strings are not routes", webApp("// Route::get('/no', [UserController::class, 'a']);\n$s = \"Route::get('/no2', 'x')\";\n/* Route::get('/no3', 'x'); */\nRoute::get('/yes', [UserController::class, 'a']);\n", nil),
			[]string{"GET /yes"}},
		{"router variable", webApp("$router->get('/old', 'UserController@index');\n$router->group(['prefix' => 'v1'], function ($router) {\n    $router->delete('/users/{id}', 'UserController@destroy');\n});\n", nil),
			[]string{"DELETE /v1/users/{id}", "GET /old"}},
		{"a prefix built at run time is not guessed", webApp("Route::prefix($p)->group(function () {\n    Route::get('/no', [UserController::class, 'a']);\n});\nRoute::prefix('v' . $n)->get('/no2', [UserController::class, 'a']);\nRoute::get('/yes', [UserController::class, 'a']);\n", nil),
			[]string{"GET /yes"}},
		{"route files outside routes/ are not read", map[string]string{"app/helpers.php": phpHead + "Route::get('/no', 'x');\n"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := routeKeys(a); !slices.Equal(got, c.want) {
				t.Fatalf("routes = %v, want %v", got, c.want)
			}
			for _, r := range a.Routes() {
				if r.Reader != ReaderLaravel {
					t.Errorf("%s %s Reader = %q", r.Method, r.Path, r.Reader)
				}
			}
			if a.RoutesRead() != len(a.Routes()) {
				t.Errorf("RoutesRead %d != %d", a.RoutesRead(), len(a.Routes()))
			}
		})
	}
}

func TestLaravelRouteCarriesFileAndLine(t *testing.T) {
	a, _ := scanFiles(t, webApp("\nRoute::delete('/users/{id}', [UserController::class, 'destroy']);\n", nil))
	rs := a.Routes()
	if len(rs) != 1 || rs[0].FilePath != "routes/web.php" || rs[0].Line != 8 {
		t.Fatalf("routes = %+v", rs)
	}
}

func destroyRoute() string {
	return "Route::delete('/users/{id}', [UserController::class, 'destroy']);\n"
}

func mergeFiles(ms ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// The unsafe variants: routes that meet AUTHN-001's proposition.
func TestLaravelMissingAuthenticationLeads(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"no middleware", webApp(destroyRoute(), userCtl("")), []string{"DELETE /users/{id}"}},
		{"api.php is not authenticated by default", mergeFiles(map[string]string{"routes/api.php": phpHead + destroyRoute()}, userCtl("")), []string{"DELETE /api/users/{id}"}},
		{"verified is not authentication", webApp("Route::middleware(['verified'])->group(function () {\n    "+destroyRoute()+"});\n", userCtl("")), []string{"DELETE /users/{id}"}},
		{"guest is the opposite of authentication", webApp("Route::middleware('guest')->group(function () {\n    "+destroyRoute()+"});\n", userCtl("")), []string{"DELETE /users/{id}"}},
		{"throttle is not authentication", webApp("Route::middleware('throttle:60,1')->delete('/users/{id}', [UserController::class, 'destroy']);\n", userCtl("")), []string{"DELETE /users/{id}"}},
		{"the group closed before the route", webApp("Route::middleware('auth')->group(function () {\n    Route::get('/me', [UserController::class, 'me']);\n});\n"+destroyRoute(), userCtl("")), []string{"DELETE /users/{id}"}},
		{"a sibling route's middleware does not cover it", webApp("Route::get('/me', [UserController::class, 'me'])->middleware('auth');\n"+destroyRoute(), userCtl("")), []string{"DELETE /users/{id}"}},
		{"withoutMiddleware removes the group's auth", webApp("Route::middleware('auth')->group(function () {\n    Route::delete('/users/{id}', [UserController::class, 'destroy'])->withoutMiddleware('auth');\n});\n", userCtl("")), []string{"DELETE /users/{id}"}},
		{"constructor auth only for other actions", webApp(destroyRoute(), userCtl("    public function __construct()\n    {\n        $this->middleware('auth')->only(['index', 'show']);\n    }\n")), []string{"DELETE /users/{id}"}},
		{"constructor auth except this action", webApp(destroyRoute(), userCtl("    public function __construct()\n    {\n        $this->middleware('auth')->except(['destroy']);\n    }\n")), []string{"DELETE /users/{id}"}},
		{"constructor guest middleware", webApp(destroyRoute(), userCtl("    public function __construct()\n    {\n        $this->middleware('guest');\n    }\n")), []string{"DELETE /users/{id}"}},
		{"auth only in a commented constructor", webApp(destroyRoute(), userCtl("    // $this->middleware('auth');\n")), []string{"DELETE /users/{id}"}},
		{"other controller's constructor", webApp(destroyRoute(), mergeFiles(userCtl(""), map[string]string{"app/Http/Controllers/PostController.php": phpController("PostController", "Controller", "    public function __construct() { $this->middleware('auth'); }\n")})), []string{"DELETE /users/{id}"}},
		{"redirect-if-authenticated is the opposite of authentication", webApp("Route::middleware([\\App\\Http\\Middleware\\RedirectIfAuthenticated::class])->group(function () {\n    "+destroyRoute()+"});\n", userCtl("")), []string{"DELETE /users/{id}"}},
		{"AuthenticateSession does not require a login", webApp("Route::middleware(['auth.session'])->group(function () {\n    "+destroyRoute()+"});\nRoute::middleware(\\Illuminate\\Session\\Middleware\\AuthenticateSession::class)->get('/admin/x', [UserController::class, 'x']);\n", userCtl("")), []string{"DELETE /users/{id}", "GET /admin/x"}},
		{"a provider maps a routes file with no authentication", mergeFiles(map[string]string{"routes/admin.php": phpHead + destroyRoute(), "app/Providers/RouteServiceProvider.php": "<?php\nclass RouteServiceProvider {\n public function boot() {\n  $this->routes(function () {\n   Route::middleware('web')->prefix('admin')->group(base_path('routes/admin.php'));\n  });\n }\n}\n"}, userCtl("")), []string{"DELETE /admin/users/{id}"}},
		{"AuthorizesRequests and ValidatesRequests say nothing about the caller", webApp(destroyRoute(), map[string]string{"app/Http/Controllers/Controller.php": baseCtl, "app/Http/Controllers/UserController.php": "<?php\nnamespace App\\Http\\Controllers;\nclass UserController extends Controller\n{\n    use AuthorizesRequests, ValidatesRequests;\n" + phpDestroy + "}\n"}), []string{"DELETE /users/{id}"}},
		{"a closure handler with no check", webApp("Route::delete('/users/{id}', function ($id) {\n    return $id;\n});\n", nil), []string{"DELETE /users/{id}"}},
		{"admin path on a GET", webApp("Route::get('/admin/report', [UserController::class, 'report']);\n", userCtl("")), []string{"GET /admin/report"}},
		{"apiResource, mutating verbs and the record GET", webApp("Route::apiResource('users', UserController::class);\n", userCtl("    public function show($id) {}\n    public function update($id) {}\n")),
			[]string{"DELETE /users/{user}", "GET /users/{user}", "PATCH /users/{user}", "PUT /users/{user}"}},
		{"auth on only some of a resource", webApp("Route::apiResource('users', UserController::class)->only(['index']);\nRoute::apiResource('users2', UserController::class)->only(['destroy'])->middleware('auth:sanctum');\nRoute::apiResource('users3', UserController::class)->only(['destroy']);\n", userCtl("")),
			[]string{"DELETE /users3/{users3}"}},
		{"a global group guard in another project", map[string]string{
			"a/routes/web.php":                          phpHead + destroyRoute(),
			"b/app/Http/Kernel.php":                     "<?php\nclass Kernel {\n protected $middleware = [\n  \\Illuminate\\Auth\\Middleware\\Authenticate::class,\n ];\n}\n",
			"a/app/Http/Controllers/UserController.php": phpController("UserController", "Controller", phpDestroy),
			"a/app/Http/Controllers/Controller.php":     baseCtl,
			"b/routes/web.php":                          phpHead + "Route::get('/x', 'UserController@x');\n"},
			[]string{"DELETE /users/{id}"}},
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

func kernel(body string) map[string]string {
	return map[string]string{"app/Http/Kernel.php": "<?php\nnamespace App\\Http;\nclass Kernel extends HttpKernel\n{\n" + body + "}\n"}
}

// The safe variants: each shows access control, or hides it from this reader.
func TestLaravelSafeVariantsAreNotLeads(t *testing.T) {
	ctl := userCtl("")
	grp := func(mw string) map[string]string {
		return webApp(mw+"->group(function () {\n    "+destroyRoute()+"});\n", ctl)
	}
	cases := map[string]map[string]string{
		"middleware auth group":                  grp("Route::middleware('auth')"),
		"middleware array":                       grp("Route::middleware(['web', 'auth'])"),
		"auth:sanctum":                           grp("Route::middleware('auth:sanctum')"),
		"auth with verified":                     grp("Route::middleware(['auth', 'verified'])"),
		"Authenticate class":                     grp("Route::middleware([\\Illuminate\\Auth\\Middleware\\Authenticate::class])"),
		"auth.basic":                             grp("Route::middleware('auth.basic')"),
		"jwt alias by name":                      grp("Route::middleware('jwt.auth')"),
		"can is an authorization gate":           grp("Route::middleware('can:delete,user')"),
		"role middleware":                        grp("Route::middleware('role:admin')"),
		"modifiers in either order":              grp("Route::prefix('x')->middleware('auth')->name('a.')"),
		"on the route":                           webApp("Route::delete('/users/{id}', [UserController::class, 'destroy'])->middleware('auth');\n", ctl),
		"on the route, array":                    webApp("Route::delete('/users/{id}', [UserController::class, 'destroy'])->middleware(['auth', 'verified']);\n", ctl),
		"before the verb":                        webApp("Route::middleware('auth')->delete('/users/{id}', [UserController::class, 'destroy']);\n", ctl),
		"can on the route":                       webApp("Route::delete('/users/{id}', [UserController::class, 'destroy'])->can('delete', 'user');\n", ctl),
		"on a resource":                          webApp("Route::apiResource('users', UserController::class)->middleware('auth:sanctum');\n", ctl),
		"nested groups":                          webApp("Route::middleware('auth')->group(function () {\n    Route::prefix('a')->group(function () {\n        "+destroyRoute()+"    });\n});\n", ctl),
		"array form group":                       webApp("Route::group(['middleware' => 'auth', 'prefix' => 'a'], function () {\n    "+destroyRoute()+"});\n", ctl),
		"array form group, middleware list":      webApp("Route::group(['middleware' => ['web', 'auth']], function () {\n    "+destroyRoute()+"});\n", ctl),
		"router variable group":                  webApp("$router->group(['middleware' => 'auth'], function ($router) {\n    $router->delete('/users/{id}', 'UserController@destroy');\n});\n", ctl),
		"controller group inside auth group":     webApp("Route::middleware('auth')->controller(UserController::class)->group(function () {\n    Route::delete('/users/{id}', 'destroy');\n});\n", ctl),
		"constructor auth":                       webApp(destroyRoute(), userCtl("    public function __construct()\n    {\n        $this->middleware('auth');\n    }\n")),
		"constructor auth only this action":      webApp(destroyRoute(), userCtl("    public function __construct()\n    {\n        $this->middleware('auth')->only('destroy');\n    }\n")),
		"constructor auth except other actions":  webApp(destroyRoute(), userCtl("    public function __construct()\n    {\n        $this->middleware('auth', ['except' => ['index']]);\n    }\n")),
		"constructor auth:api":                   webApp(destroyRoute(), userCtl("    public function __construct()\n    {\n        $this->middleware('auth:api')->except(['index', 'show']);\n    }\n")),
		"authorizeResource":                      webApp("Route::resource('users', UserController::class)->only(['destroy']);\n", userCtl("    public function __construct()\n    {\n        $this->authorizeResource(User::class, 'user');\n    }\n")),
		"HasMiddleware":                          webApp(destroyRoute(), userCtl("    public static function middleware(): array\n    {\n        return [\n            new Middleware('auth', except: ['index']),\n        ];\n    }\n")),
		"HasMiddleware, bare item":               webApp(destroyRoute(), userCtl("    public static function middleware(): array\n    {\n        return ['auth'];\n    }\n")),
		"parent controller constructor":          webApp(destroyRoute(), mergeFiles(userCtl(""), map[string]string{"app/Http/Controllers/Controller.php": "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Routing\\Controller as BaseController;\nclass Controller extends BaseController\n{\n    public function __construct() { $this->middleware('auth'); }\n}\n"})),
		"intermediate base controller":           webApp(destroyRoute(), mergeFiles(map[string]string{"app/Http/Controllers/Controller.php": baseCtl, "app/Http/Controllers/AuthedController.php": phpController("AuthedController", "Controller", "    public function __construct() { $this->middleware('auth'); }\n"), "app/Http/Controllers/UserController.php": phpController("UserController", "AuthedController", phpDestroy)})),
		"inline Auth::user":                      webApp(destroyRoute(), userCtlRaw("    public function destroy($id)\n    {\n        $u = Auth::user();\n    }\n")),
		"a trait that authenticates is not seen": webApp(destroyRoute(), map[string]string{"app/Http/Controllers/Controller.php": baseCtl, "app/Http/Controllers/UserController.php": "<?php\nnamespace App\\Http\\Controllers;\nclass UserController extends Controller\n{\n    use AuthenticatesUsers;\n" + phpDestroy + "}\n"}),
		"controller of a package":                webApp(destroyRoute(), map[string]string{"app/Http/Controllers/UserController.php": phpController("UserController", "\\Vendor\\Pkg\\BaseController", phpDestroy)}),
		"controller not in the repository":       webApp(destroyRoute(), nil),
		"closure handler reads the caller":       webApp("Route::delete('/users/{id}', function ($id, Request $request) {\n    $request->user()->delete();\n});\n", nil),
		"global kernel middleware":               mergeFiles(webApp(destroyRoute(), ctl), kernel("    protected $middleware = [\n        \\Illuminate\\Auth\\Middleware\\Authenticate::class,\n    ];\n")),
		"kernel web group":                       mergeFiles(webApp(destroyRoute(), ctl), kernel("    protected $middlewareGroups = [\n        'web' => [\n            \\App\\Http\\Middleware\\EncryptCookies::class,\n            \\App\\Http\\Middleware\\RequireAuth::class,\n        ],\n        'api' => [],\n    ];\n")),
		"kernel api group, api.php":              mergeFiles(map[string]string{"routes/api.php": phpHead + destroyRoute()}, ctl, kernel("    protected $middlewareGroups = [\n        'web' => [],\n        'api' => [\n            'auth:sanctum',\n        ],\n    ];\n")),
		"bootstrap/app.php appends auth":         mergeFiles(webApp(destroyRoute(), ctl), map[string]string{"bootstrap/app.php": "<?php\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withMiddleware(function (Middleware $middleware) {\n        $middleware->web(append: [\\App\\Http\\Middleware\\EnsureAuthenticated::class]);\n    })->create();\n"}),
		"provider maps the file under auth":      mergeFiles(map[string]string{"routes/admin.php": phpHead + destroyRoute(), "app/Providers/RouteServiceProvider.php": "<?php\nclass RouteServiceProvider {\n public function boot() {\n  $this->routes(function () {\n   Route::middleware(['web', 'auth'])->prefix('admin')->group(base_path('routes/admin.php'));\n  });\n }\n}\n"}, ctl),
		"file included from an auth group":       mergeFiles(map[string]string{"routes/web.php": phpHead + "Route::middleware('auth')->group(base_path('routes/admin.php'));\n", "routes/admin.php": phpHead + destroyRoute()}, ctl),
		"unmapped extra routes file":             mergeFiles(map[string]string{"routes/admin.php": phpHead + destroyRoute()}, ctl),
		"middleware from a variable":             webApp("Route::middleware($mw)->group(function () {\n    "+destroyRoute()+"});\n", ctl),
		"prefix from a variable is unreadable":   webApp("Route::prefix($p)->middleware('auth')->group(function () {\n    "+destroyRoute()+"});\n", ctl),
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			a, _ := scanFiles(t, files)
			if len(a.Routes()) == 0 && name != "prefix from a variable is unreadable" {
				t.Fatalf("no routes read; the test would pass for the wrong reason")
			}
			if got := authnLeads(a); len(got) != 0 {
				t.Fatalf("leads = %v, want none (routes %v)", got, routeKeys(a))
			}
		})
	}
}

func TestLaravelRecordsAuthenticationOnRoutes(t *testing.T) {
	files := webApp("Route::middleware('auth:sanctum')->group(function () {\n    "+destroyRoute()+"});\nRoute::get('/pub', [UserController::class, 'pub']);\n", userCtl(""))
	a, _ := scanFiles(t, files)
	if got, ok := routeAuthn(a, "DELETE /users/{id}"); !ok || got == "" {
		t.Errorf("DELETE Authn = %q (found %v)", got, ok)
	}
	if got, ok := routeAuthn(a, "GET /pub"); !ok || got != "" {
		t.Errorf("GET /pub Authn = %q (found %v)", got, ok)
	}
}

func TestLaravelDoesNotTreatAliasedAuthnAsAuth(t *testing.T) {
	// 'checkRole' is an alias for a class that only logs: a name the reader does
	// not recognise is not authentication, so the route stays a lead.
	files := mergeFiles(webApp("Route::middleware('logreq')->group(function () {\n    "+destroyRoute()+"});\n", userCtl("")),
		kernel("    protected $routeMiddleware = [\n        'logreq' => \\App\\Http\\Middleware\\LogRequests::class,\n    ];\n"))
	a, _ := scanFiles(t, files)
	if got := authnLeads(a); !slices.Equal(got, []string{"DELETE /users/{id}"}) {
		t.Fatalf("leads = %v", got)
	}
	// ...and an alias whose class says it authenticates is.
	files = mergeFiles(webApp("Route::middleware('member')->group(function () {\n    "+destroyRoute()+"});\n", userCtl("")),
		kernel("    protected $routeMiddleware = [\n        'member' => \\App\\Http\\Middleware\\RequireLogin::class,\n    ];\n"))
	a, _ = scanFiles(t, files)
	if got := authnLeads(a); len(got) != 0 {
		t.Fatalf("leads = %v", got)
	}
}

// A resource over a controller that lacks the method is not a reachable
// endpoint: calling it is an exception, not the data.
func TestLaravelRouteToAnUndefinedMethodIsNotALead(t *testing.T) {
	cases := []struct {
		name string
		ctl  string
		want []string
	}{
		{"defined", phpDestroy + "    public function update($id) {}\n", []string{"DELETE /users/{user}", "PATCH /users/{user}", "PUT /users/{user}"}},
		{"only destroy", phpDestroy, []string{"DELETE /users/{user}"}},
		{"nothing", "    public function index() {}\n", nil},
		{"a trait may define it", "    use SomeCrud;\n", []string{"DELETE /users/{user}", "PATCH /users/{user}", "PUT /users/{user}"}},
		{"__call may answer it", "    public function __call($m, $a) {}\n", []string{"DELETE /users/{user}", "PATCH /users/{user}", "PUT /users/{user}"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := webApp("Route::resource('users', UserController::class)->only(['update', 'destroy']);\n", userCtlRaw(c.ctl))
			a, _ := scanFiles(t, files)
			if got := authnLeads(a); !slices.Equal(got, c.want) {
				t.Fatalf("leads = %v, want %v", got, c.want)
			}
		})
	}
}
