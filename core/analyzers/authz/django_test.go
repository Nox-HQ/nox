package authz

import (
	"slices"
	"testing"
)

const djRoot = "from django.urls import path, include\n"

func djProject(urls, views string, extra ...string) map[string]string {
	files := map[string]string{
		"proj/urls.py":     djRoot + "urlpatterns = [\n    path('api/', include('shop.urls')),\n]\n",
		"shop/urls.py":     "from django.urls import path\nfrom . import views\n" + urls,
		"shop/views.py":    views,
		"shop/__init__.py": "",
		"proj/__init__.py": "",
	}
	for i := 0; i+1 < len(extra); i += 2 {
		files[extra[i]] = extra[i+1]
	}
	return files
}

// The unsafe variants: Django routes that meet AUTHN-001's proposition.
func TestDjangoMissingAuthenticationLeads(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"function view, admin path", djProject("urlpatterns = [path('admin/users/', views.users)]\n",
			"from django.http import JsonResponse\ndef users(request):\n    return JsonResponse({})\n"),
			[]string{"ALL /api/admin/users"}},
		{"delete by id with require_http_methods", djProject("urlpatterns = [path('orders/<int:pk>/', views.cancel)]\n",
			"from django.views.decorators.http import require_http_methods\n@require_http_methods(['DELETE'])\ndef cancel(request, pk):\n    return None\n"),
			[]string{"DELETE /api/orders/:pk"}},
		{"class view put", djProject("urlpatterns = [path('invoices/<int:pk>/', views.InvoiceView.as_view())]\n",
			"from django.views import View\nclass InvoiceView(View):\n    def put(self, request, pk):\n        return None\n"),
			[]string{"PUT /api/invoices/:pk"}},
		{"drf apiview delete", djProject("urlpatterns = [path('accounts/<int:pk>/', views.AccountAPI.as_view())]\n",
			"from rest_framework.views import APIView\nclass AccountAPI(APIView):\n    def delete(self, request, pk):\n        return None\n"),
			[]string{"DELETE /api/accounts/:pk"}},
		{"re_path", djProject("from django.urls import re_path\nurlpatterns = [re_path(r'^admin/export/$', views.export)]\n",
			"def export(request):\n    return None\n"),
			[]string{"ALL /api/admin/export"}},
		{"drf router, modelviewset", map[string]string{
			"proj/urls.py":     djRoot + "from rest_framework.routers import DefaultRouter\nfrom shop import views\nrouter = DefaultRouter()\nrouter.register(r'accounts', views.AccountViewSet)\nurlpatterns = [path('api/', include(router.urls))]\n",
			"shop/views.py":    "from rest_framework import viewsets\nclass AccountViewSet(viewsets.ModelViewSet):\n    queryset = None\n",
			"shop/__init__.py": "", "proj/__init__.py": ""},
			[]string{"DELETE /api/accounts/:pk", "GET /api/accounts/:pk", "PATCH /api/accounts/:pk", "PUT /api/accounts/:pk"}},
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

// The safe variants: each shows access control or intent the reader must see.
func TestDjangoSafeVariantsAreNotLeads(t *testing.T) {
	cases := map[string]map[string]string{
		"login_required": djProject("urlpatterns = [path('admin/users/', views.users)]\n",
			"from django.contrib.auth.decorators import login_required\n@login_required\ndef users(request):\n    return None\n"),
		"stacked decorators": djProject("urlpatterns = [path('orders/<int:pk>/', views.cancel)]\n",
			"from django.views.decorators.http import require_http_methods\n@require_http_methods(['DELETE'])\n@permission_required('shop.cancel')\ndef cancel(request, pk):\n    return None\n"),
		"LoginRequiredMixin": djProject("urlpatterns = [path('invoices/<int:pk>/', views.InvoiceView.as_view())]\n",
			"from django.contrib.auth.mixins import LoginRequiredMixin\nfrom django.views import View\nclass InvoiceView(LoginRequiredMixin, View):\n    def put(self, request, pk):\n        return None\n"),
		"mixin on a base class in the repo": djProject("urlpatterns = [path('invoices/<int:pk>/', views.InvoiceView.as_view())]\n",
			"from django.contrib.auth.mixins import LoginRequiredMixin\nfrom django.views import View\nclass Base(LoginRequiredMixin, View):\n    pass\nclass InvoiceView(Base):\n    def put(self, request, pk):\n        return None\n"),
		"method_decorator on dispatch": djProject("urlpatterns = [path('invoices/<int:pk>/', views.InvoiceView.as_view())]\n",
			"from django.utils.decorators import method_decorator\nfrom django.views import View\n@method_decorator(login_required, name='dispatch')\nclass InvoiceView(View):\n    def put(self, request, pk):\n        return None\n"),
		"drf permission_classes": djProject("urlpatterns = [path('accounts/<int:pk>/', views.AccountAPI.as_view())]\n",
			"from rest_framework.views import APIView\nclass AccountAPI(APIView):\n    permission_classes = [IsAuthenticated]\n    def delete(self, request, pk):\n        return None\n"),
		"drf api_view with permission_classes decorator": djProject("urlpatterns = [path('admin/purge/', views.purge)]\n",
			"@api_view(['POST'])\n@permission_classes([IsAdminUser])\ndef purge(request):\n    return None\n"),
		"explicitly public with AllowAny": djProject("urlpatterns = [path('accounts/<int:pk>/', views.AccountAPI.as_view())]\n",
			"from rest_framework.views import APIView\nclass AccountAPI(APIView):\n    permission_classes = [AllowAny]\n    def delete(self, request, pk):\n        return None\n"),
		"authentication disabled on purpose": djProject("urlpatterns = [path('accounts/<int:pk>/', views.AccountAPI.as_view())]\n",
			"from rest_framework.views import APIView\nclass AccountAPI(APIView):\n    authentication_classes = []\n    def delete(self, request, pk):\n        return None\n"),
		"inline check on the caller": djProject("urlpatterns = [path('admin/users/', views.users)]\n",
			"def users(request):\n    if not request.user.is_authenticated:\n        return None\n    return None\n"),
		"project-wide DRF default": djProject("urlpatterns = [path('accounts/<int:pk>/', views.AccountAPI.as_view())]\n",
			"from rest_framework.views import APIView\nclass AccountAPI(APIView):\n    def delete(self, request, pk):\n        return None\n",
			"proj/settings.py", "REST_FRAMEWORK = {\n    'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated'],\n}\n"),
		"login required middleware": djProject("urlpatterns = [path('admin/users/', views.users)]\n",
			"def users(request):\n    return None\n",
			"proj/settings.py", "MIDDLEWARE = [\n    'django.contrib.auth.middleware.AuthenticationMiddleware',\n    'django.contrib.auth.middleware.LoginRequiredMiddleware',\n]\n"),
		"custom auth middleware this reader cannot evaluate": djProject("urlpatterns = [path('admin/users/', views.users)]\n",
			"def users(request):\n    return None\n",
			"proj/settings.py", "MIDDLEWARE = [\n    'myapp.middleware.JWTAuthMiddleware',\n]\n"),
		"public by name": djProject("urlpatterns = [path('login/', views.login_view), path('health/', views.health)]\n",
			"def login_view(request):\n    return None\ndef health(request):\n    return None\n"),
		"a view the reader cannot find": djProject("urlpatterns = [path('admin/users/', somewhere.users)]\n",
			"def other(request):\n    return None\n"),

		// The admin site authenticates its own users.
		"django admin site": {"proj/urls.py": djRoot + "from django.contrib import admin\nurlpatterns = [path('admin/', admin.site.urls)]\n"},
		"test fixture":      {"tests/urls.py": djRoot + "urlpatterns = [path('admin/users/', lambda r: None)]\n"},
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

// IsAuthenticatedOrReadOnly authenticates the writes only.
func TestDjangoReadOnlyAuthenticationDoesNotCoverWrites(t *testing.T) {
	a, _ := scanFiles(t, djProject("urlpatterns = [path('accounts/<int:pk>/', views.AccountAPI.as_view())]\n",
		"from rest_framework.views import APIView\nclass AccountAPI(APIView):\n    permission_classes = [IsAuthenticatedOrReadOnly]\n    def get(self, request, pk):\n        return None\n    def delete(self, request, pk):\n        return None\n"))
	rs := map[string]string{}
	for _, r := range a.Routes() {
		rs[r.Method] = r.Authn
	}
	if rs["DELETE"] != "IsAuthenticatedOrReadOnly" || rs["GET"] != "" {
		t.Fatalf("authn by method = %v; the writes are authenticated, the read is not", rs)
	}
	if got := authnLeads(a); len(got) != 0 {
		t.Fatalf("GET /api/accounts/:pk of an IsAuthenticatedOrReadOnly view is public by declaration: %v", got)
	}
}

func TestDjangoRouteTable(t *testing.T) {
	a, _ := scanFiles(t, djProject("urlpatterns = [\n    path('items/', views.ItemList.as_view()),\n    path('items/<slug:slug>/', views.item_detail),\n]\n",
		"from django.contrib.auth.decorators import login_required\nfrom django.views.generic import ListView\nclass ItemList(ListView):\n    pass\n@login_required\ndef item_detail(request, slug):\n    return None\n"))
	want := []string{"ALL /api/items/:slug", "GET /api/items"}
	if got := routeKeys(a); !slices.Equal(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	for _, r := range a.Routes() {
		if r.Path == "/api/items/:slug" && r.Authn != "login_required" {
			t.Errorf("item_detail authn = %q", r.Authn)
		}
		if r.FilePath != "shop/urls.py" || r.Line == 0 {
			t.Errorf("route must locate its registration: %+v", r)
		}
	}
}

func TestDjangoUnverifiedStripeWebhook(t *testing.T) {
	_, fs := scanFiles(t, djProject("urlpatterns = [path('webhooks/stripe/', views.stripe_hook)]\n",
		"def stripe_hook(request):\n    event = json.loads(request.body)\n    return None\n"))
	// The view serves every method (no restriction), which the webhook check reads as ALL.
	if got := webhookFindings(fs); !slices.Equal(got, []string{"ALL /api/webhooks/stripe"}) {
		t.Fatalf("unsigned webhook = %v", got)
	}
	_, fs = scanFiles(t, djProject("urlpatterns = [path('webhooks/stripe/', views.stripe_hook)]\n",
		"def stripe_hook(request):\n    event = stripe.Webhook.construct_event(request.body, request.META['HTTP_STRIPE_SIGNATURE'], secret)\n    return None\n"))
	if got := webhookFindings(fs); len(got) != 0 {
		t.Fatalf("a verified webhook must not be reported: %v", got)
	}
}

// The healthchecks shape: a dispatcher view that hands each method to an
// @authorize'd function. The dispatcher has no decorator of its own; the access
// control is in what it calls, and the reader follows one level.
func TestDjangoDispatcherInheritsTheAccessControlOfWhatItCalls(t *testing.T) {
	views := "def authorize(f):\n    return f\n\n@authorize\ndef delete_check(request, code):\n    return None\n\n" +
		"def single(request, code):\n    if request.method == 'DELETE':\n        return delete_check(request, code)\n    return None\n"
	a, _ := scanFiles(t, djProject("urlpatterns = [path('checks/<uuid:code>', views.single)]\n", views))
	if got := authnLeads(a); len(got) != 0 {
		t.Fatalf("a dispatcher to an @authorize'd function is not a missing-authentication lead: %v", got)
	}
	// Control: the same dispatcher calling an undecorated function is.
	plain := "def delete_check(request, code):\n    return None\n\n" +
		"def single(request, code):\n    if request.method == 'DELETE':\n        return delete_check(request, code)\n    return None\n"
	a, _ = scanFiles(t, djProject("urlpatterns = [path('checks/<uuid:code>', views.single)]\n", plain))
	if got := authnLeads(a); !slices.Equal(got, []string{"DELETE /api/checks/:code"}) {
		t.Fatalf("control: leads = %v", got)
	}
}
