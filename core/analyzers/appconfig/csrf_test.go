package appconfig

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// Spring Security turns CSRF protection off, or off for some routes, in its
// filter chain configuration.
func TestSpringCSRFDisabled(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []int
	}{
		{"chained disable", "http\n    .csrf().disable()\n    .authorizeRequests();\n", []int{2}},
		{"lambda disable", "http.csrf(csrf -> csrf.disable());\n", []int{1}},
		{"method reference", "http.csrf(AbstractHttpConfigurer::disable);\n", []int{1}},
		{"reactive spec", "http.csrf(ServerHttpSecurity.CsrfSpec::disable);\n", []int{1}},
		{"routes exempted", "http.csrf(csrf -> csrf.ignoringRequestMatchers(\"/documents/**\"));\n", []int{1}},
		{"chained exemption", "http.csrf().ignoringAntMatchers(\"/api/**\");\n", []int{1}},
		{"exemption list on the next line", "http.csrf(csrf -> csrf\n        .ignoringRequestMatchers(\"/journey/**\"));\n", []int{1}},
		// Not reported.
		{"CSRF configured", "http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));\n", nil},
		{"default CSRF", "http.csrf(Customizer.withDefaults());\n", nil},
		{"in a comment", "// http.csrf().disable();\n", nil},
		{"another disable", "http.headers().frameOptions().disable();\n", nil},
	} {
		var got []int
		for _, f := range ScanFile("SecurityConfig.java", lexctx.LangJava, []byte(c.src)) {
			if f.RuleID == RuleCSRFDisabled {
				got = append(got, f.Location.StartLine)
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: lines %v, want %v", c.name, got, c.want)
		}
	}
}

// Kotlin's DSL writes the same switch.
func TestKotlinCSRFDisabled(t *testing.T) {
	src := "http {\n    csrf { disable() }\n}\n"
	var got []int
	for _, f := range ScanFile("SecurityConfig.kt", lexctx.LangKotlin, []byte(src)) {
		if f.RuleID == RuleCSRFDisabled {
			got = append(got, f.Location.StartLine)
		}
	}
	if !slices.Equal(got, []int{2}) {
		t.Errorf("lines %v, want [2]", got)
	}
}

// Django and Flask-WTF switch CSRF protection off per view, per
// authentication class, or for the whole application.
func TestPythonCSRFDisabled(t *testing.T) {
	const mw = "MIDDLEWARE = [\n    'django.contrib.sessions.middleware.SessionMiddleware',\n"
	for _, c := range []struct {
		name, path, src string
		want            []int
	}{
		{"view decorator", "app/views.py", "from django.views.decorators.csrf import csrf_exempt\n\n@csrf_exempt\ndef transfer(request):\n    Transfer.objects.create(amount=request.POST['amount'])\n", []int{3}},
		{"wrapped in a URL pattern", "app/urls.py", "urlpatterns = [path('pay/', csrf_exempt(views.pay))]\n", []int{1}},
		{"DRF enforce_csrf that does nothing", "app/auth.py", "class NoCsrf(SessionAuthentication):\n    def enforce_csrf(self, request):\n        return\n", []int{2}},
		{"DRF enforce_csrf that passes", "app/auth.py", "class NoCsrf(SessionAuthentication):\n    def enforce_csrf(self, request):\n        pass\n", []int{2}},
		{"Flask-WTF exemption", "app.py", "csrf = CSRFProtect(app)\n\n@csrf.exempt\n@app.route('/hook', methods=['POST'])\ndef hook():\n    pass\n", []int{3}},
		{"Flask-WTF off", "config.py", "WTF_CSRF_ENABLED = False\n", []int{1}},
		{"Flask-WTF off in app.config", "app.py", "app.config['WTF_CSRF_ENABLED'] = False\n", []int{1}},
		{"middleware commented out", "proj/settings.py", mw + "    # 'django.middleware.csrf.CsrfViewMiddleware',\n]\n", []int{3}},
		{"middleware never listed", "proj/settings.py", mw + "    'django.middleware.common.CommonMiddleware',\n]\n", []int{1}},
		// Not reported.
		{"middleware kept", "proj/settings.py", mw + "    'django.middleware.csrf.CsrfViewMiddleware',\n]\n", nil},
		{"no sessions, nothing to forge", "proj/settings.py", "MIDDLEWARE = [\n    'django.middleware.common.CommonMiddleware',\n]\n", nil},
		{"local settings are not deployed", "proj/settings_local.py", mw + "]\n", nil},
		{"enforce_csrf that checks", "app/auth.py", "class C(SessionAuthentication):\n    def enforce_csrf(self, request):\n        return super().enforce_csrf(request)\n", nil},
		{"Flask-WTF on", "config.py", "WTF_CSRF_ENABLED = True\n", nil},
		{"the decorator named in a comment", "app/views.py", "# @csrf_exempt is not used here\ndef f(request):\n    pass\n", nil},
		{"csrf_protect is the opposite", "app/views.py", "@csrf_protect\ndef f(request):\n    pass\n", nil},
	} {
		var got []int
		for _, f := range ScanFile(c.path, lexctx.LangPython, []byte(c.src)) {
			if f.RuleID == RuleCSRFDisabled {
				got = append(got, f.Location.StartLine)
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: lines %v, want %v", c.name, got, c.want)
		}
	}
}

// @csrf_exempt is the fix, not the defect, on a view no browser session can
// drive: one that serves only safe methods, or authenticates by header, key
// or signature.
func TestCSRFExemptInContext(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []int
	}{
		{"session view that accepts POST", "@csrf_exempt\ndef transfer(request):\n    if request.method == 'POST':\n        move(request.user, request.POST['amount'])\n", []int{1}},
		{"exempt under another decorator", "@login_required\n@csrf_exempt\ndef save_profile(request):\n    request.user.profile.save()\n", []int{2}},
		// Not reported.
		{"GET only by decorator", "@csrf_exempt\n@require_http_methods([\"GET\"])\ndef whoami(request):\n    request.user.touch.save()\n    return JsonResponse({})\n", nil},
		{"GET only by its body", "@csrf_exempt\ndef courses(request):\n    if request.method != \"GET\":\n        return JsonResponse({}, status=405)\n    key.save()\n    return JsonResponse({})\n", nil},
		{"API key in a header", "@csrf_exempt\ndef ingest(request):\n    key = request.META.get('HTTP_X_API_KEY')\n    Event.objects.create(data=request.body)\n    return JsonResponse({})\n", nil},
		{"signed webhook", "@csrf_exempt\ndef stripe_hook(request):\n    sig = request.headers.get('Stripe-Signature')\n    hmac.compare_digest(sig, expected)\n    Order.objects.create(data=request.body)\n", nil},
		{"inside a key-checking decorator", "def api_key_required(view):\n    @wraps(view)\n    @csrf_exempt\n    def wrapper(request):\n        key = APIKey.authenticate(request.META.get('HTTP_X_API_KEY'))\n        return view(request)\n    return wrapper\n", nil},
		{"the evidence belongs to the next view, not this one", "@csrf_exempt\ndef pay(request):\n    Payment.objects.create(user=request.user)\n\ndef other(request):\n    request.META.get('HTTP_X_API_KEY')\n", []int{1}},
		{"key named only in a comment", "@csrf_exempt\ndef pay(request):\n    # TODO: check request.META api_key here\n    Payment.objects.create(user=request.user)\n", []int{1}},
		{"a view that only reads", "@csrf_exempt\ndef employees(request):\n    return JsonResponse({'e': list(Employee.objects.values())})\n", nil},
	} {
		var got []int
		for _, f := range ScanFile("app/views.py", lexctx.LangPython, []byte(c.src)) {
			if f.RuleID == RuleCSRFDisabled {
				got = append(got, f.Location.StartLine)
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: lines %v, want %v", c.name, got, c.want)
		}
	}
}
