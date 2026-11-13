package authz

import (
	"slices"
	"testing"
)

// railsApp is a minimal repository: a routes file and the controllers it names.
func railsApp(routes string, ctrls map[string]string) map[string]string {
	files := map[string]string{"config/routes.rb": "Rails.application.routes.draw do\n" + routes + "end\n"}
	for name, body := range ctrls {
		files["app/controllers/"+name] = body
	}
	return files
}

func rbCtl(class, super, body string) string {
	return "class " + class + " < " + super + "\n" + body + "end\n"
}

func routeAuthn(a *Analyzer, key string) (string, bool) {
	for _, r := range a.Routes() {
		if r.Method+" "+r.Path == key {
			return r.Authn + r.Authz, true
		}
	}
	return "", false
}

func TestRailsRouteTable(t *testing.T) {
	cases := []struct {
		name   string
		routes string
		want   []string
	}{
		{"verbs with to", "  get '/users/:id', to: 'users#show'\n  post 'users', to: 'users#create'\n  put 'users/:id' => 'users#update'\n  patch '/users/:id', to: 'users#update'\n  delete '/users/:id', to: 'users#destroy'\n",
			[]string{"DELETE /users/:id", "GET /users/:id", "PATCH /users/:id", "POST /users", "PUT /users/:id"}},
		{"resources", "  resources :users\n",
			[]string{"DELETE /users/:id", "GET /users", "GET /users/:id", "GET /users/:id/edit", "GET /users/new", "PATCH /users/:id", "POST /users", "PUT /users/:id"}},
		{"only and except", "  resources :users, only: [:index, :show]\n  resources :posts, except: %i[new edit destroy]\n",
			[]string{"GET /posts", "GET /posts/:id", "GET /users", "GET /users/:id", "PATCH /posts/:id", "POST /posts", "PUT /posts/:id"}},
		{"singular resource", "  resource :profile, only: [:show, :update]\n",
			[]string{"GET /profile", "PATCH /profile", "PUT /profile"}},
		{"namespace and scope", "  namespace :admin do\n    resources :users, only: :destroy\n  end\n  scope '/api' do\n    get 'ping2', to: 'health#show'\n  end\n  scope '/v2', module: 'v2' do\n    delete 'x/:id', to: 'x#destroy'\n  end\n",
			[]string{"DELETE /admin/users/:id", "DELETE /v2/x/:id", "GET /api/ping2"}},
		{"nested resources, member and collection", "  resources :posts, only: [] do\n    resources :comments, only: [:index, :destroy]\n    member do\n      post :publish\n    end\n    collection do\n      get :search\n    end\n  end\n",
			[]string{"DELETE /posts/:post_id/comments/:id", "GET /posts/:post_id/comments", "GET /posts/search", "POST /posts/:id/publish"}},
		{"on: option and bare nested verb", "  resources :posts, only: [] do\n    get :preview, on: :member\n    get :archive, on: :collection\n    get :stats\n  end\n",
			[]string{"GET /posts/:id/preview", "GET /posts/:post_id/stats", "GET /posts/archive"}},
		{"match via", "  match 'sync', to: 'sync#run', via: [:get, :post]\n  match 'any', to: 'sync#run', via: :all\n",
			[]string{"ALL /any", "GET /sync", "POST /sync"}},
		{"controller block and implicit controller", "  controller :sessions do\n    get 'login2' => :new\n  end\n  get 'photos/show'\n",
			[]string{"GET /photos/show"}},
		{"root and optional segments", "  root 'home#index'\n  scope '(:locale)' do\n    get 'about', to: 'pages#about'\n  end\n  get 'files/:id(.:format)', to: 'files#show'\n",
			[]string{"GET /", "GET /about", "GET /files/:id"}},
		{"rack apps, redirects and mounts are not controller routes", "  get '/old', to: redirect('/new')\n  mount Sidekiq::Web => '/sidekiq'\n  get '/health', to: HealthCheck\n  devise_for :users\n  get '/ok', to: 'ok#show'\n",
			[]string{"GET /ok"}},
		{"concern bodies are not routes", "  concern :commentable do\n    resources :comments\n  end\n  get '/z', to: 'z#show'\n",
			[]string{"GET /z"}},
		{"multi-line statements and comments", "  # get '/no', to: 'no#show'\n  resources :users,\n    only: [:index,\n           :show]\n  get '/yes', to: 'yes#show' # trailing\n",
			[]string{"GET /users", "GET /users/:id", "GET /yes"}},
		{"heredoc and string content are not code", "  x = <<~EOS\n    get '/fake', to: 'fake#show'\n    end\n  EOS\n  get '/real', to: 'real#show'\n",
			[]string{"GET /real"}},
		{"conditional blocks still close", "  if Rails.env.development?\n    get '/dev', to: 'dev#show'\n  end\n  get '/after', to: 'after#show'\n",
			[]string{"GET /after", "GET /dev"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, railsApp(c.routes, nil))
			if got := routeKeys(a); !slices.Equal(got, c.want) {
				t.Fatalf("routes = %v, want %v", got, c.want)
			}
			for _, r := range a.Routes() {
				if r.Reader != ReaderRails {
					t.Errorf("%s %s Reader = %q", r.Method, r.Path, r.Reader)
				}
			}
			if a.RoutesRead() != len(a.Routes()) {
				t.Errorf("RoutesRead %d != %d", a.RoutesRead(), len(a.Routes()))
			}
		})
	}
}

func TestRailsRouteCarriesFileAndLine(t *testing.T) {
	a, _ := scanFiles(t, railsApp("\n  delete '/users/:id', to: 'users#destroy'\n", nil))
	rs := a.Routes()
	if len(rs) != 1 || rs[0].FilePath != "config/routes.rb" || rs[0].Line != 3 {
		t.Fatalf("routes = %+v", rs)
	}
}

const (
	usersDestroy = "  def destroy\n    User.find(params[:id]).destroy\n  end\n"
	delRoute     = "  delete '/users/:id', to: 'users#destroy'\n"
)

func usersCtl(super, body string) map[string]string {
	return map[string]string{"users_controller.rb": rbCtl("UsersController", super, body+usersDestroy)}
}

// The unsafe variants: routes that meet AUTHN-001's proposition.
func TestRailsMissingAuthenticationLeads(t *testing.T) {
	appCtl := map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::Base", "")}
	with := func(ctrls ...map[string]string) map[string]string {
		out := map[string]string{}
		for _, m := range ctrls {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}
	cases := []struct {
		name   string
		routes string
		ctrls  map[string]string
		want   []string
	}{
		{"no callbacks anywhere", delRoute, with(appCtl, usersCtl("ApplicationController", "")), []string{"DELETE /users/:id"}},
		{"resources, only the mutating verbs and the record GET", "  resources :users\n", with(appCtl, usersCtl("ApplicationController", "  def show; end\n  def edit; end\n  def update; end\n")),
			[]string{"DELETE /users/:id", "GET /users/:id", "GET /users/:id/edit", "PATCH /users/:id", "PUT /users/:id"}},
		{"auth callback limited to other actions", delRoute, with(appCtl, usersCtl("ApplicationController", "  before_action :authenticate_user!, only: [:index, :show]\n")), []string{"DELETE /users/:id"}},
		{"except names this action", delRoute, with(appCtl, usersCtl("ApplicationController", "  before_action :authenticate_user!, except: [:destroy]\n")), []string{"DELETE /users/:id"}},
		{"skip_before_action makes the action public", delRoute,
			with(map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::Base", "  before_action :authenticate_user!\n")},
				usersCtl("ApplicationController", "  skip_before_action :authenticate_user!, only: :destroy\n")), []string{"DELETE /users/:id"}},
		{"skip without only, whole controller", delRoute,
			with(map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::Base", "  before_action :authenticate_user!\n")},
				usersCtl("ApplicationController", "  skip_before_action :authenticate_user!\n")), []string{"DELETE /users/:id"}},
		{"csrf protection is not authentication", delRoute, with(appCtl, usersCtl("ApplicationController", "  before_action :verify_authenticity_token\n")), []string{"DELETE /users/:id"}},
		{"an optional or setter callback is not authentication", delRoute, with(appCtl, usersCtl("ApplicationController", "  before_action :set_user\n  before_action :authenticate_optional\n")), []string{"DELETE /users/:id"}},
		{"after_action is not a gate", delRoute, with(appCtl, usersCtl("ApplicationController", "  after_action :authenticate_user!\n")), []string{"DELETE /users/:id"}},
		{"authentication in a sibling controller", delRoute,
			with(appCtl, usersCtl("ApplicationController", ""), map[string]string{"admin_controller.rb": rbCtl("AdminController", "ApplicationController", "  before_action :authenticate_user!\n")}), []string{"DELETE /users/:id"}},
		{"authentication named only in a comment", delRoute, with(appCtl, usersCtl("ApplicationController", "  # before_action :authenticate_user!\n")), []string{"DELETE /users/:id"}},
		{"authentication in a string", delRoute, with(appCtl, usersCtl("ApplicationController", "  X = \"before_action :authenticate_user!\"\n")), []string{"DELETE /users/:id"}},
		{"callback inside a method is not a class callback", delRoute, with(appCtl, usersCtl("ApplicationController", "  def self.setup\n    before_action :authenticate_user!\n  end\n")), []string{"DELETE /users/:id"}},
		{"namespaced route finds the namespaced controller, not the top-level one", "  namespace :admin do\n    delete 'users/:id', to: 'users#destroy'\n  end\n",
			with(appCtl, usersCtl("ApplicationController", "  before_action :authenticate_user!\n"),
				map[string]string{"admin/users_controller.rb": rbCtl("Admin::UsersController", "ApplicationController", usersDestroy)}), []string{"DELETE /admin/users/:id"}},
		{"unauthenticated block in routes is not evidence", "  unauthenticated do\n    delete '/users/:id', to: 'users#destroy'\n  end\n", with(appCtl, usersCtl("ApplicationController", "")), []string{"DELETE /users/:id"}},
		{"a constraint hash is not a guard", "  constraints(subdomain: 'api') do\n    delete '/users/:id', to: 'users#destroy'\n  end\n", with(appCtl, usersCtl("ApplicationController", "")), []string{"DELETE /users/:id"}},
		{"a login that writes the session is not a check on the caller", delRoute, with(appCtl, map[string]string{"users_controller.rb": rbCtl("UsersController", "ApplicationController", "  def destroy\n    user = User.authenticate(params[:email], params[:password])\n    session[:user_id] = user.id\n    @current_user ||= user\n  end\n")}), []string{"DELETE /users/:id"}},
		{"the bare name of an optional/required pair is the optional half", delRoute,
			with(map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::Base", "  before_action :authenticate_user\n  def authenticate_user\n    if request.headers['Authorization']\n      @id = decode(request.headers['Authorization']) rescue head(:unauthorized)\n    end\n  end\n  def authenticate_user!\n    head :unauthorized unless @id\n  end\n")}, usersCtl("ApplicationController", "")), []string{"DELETE /users/:id"}},
		{"a callback that only looks for a session and returns true does not authenticate", delRoute,
			with(map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::Base", "  include Authenticatable\n"),
				"concerns/authenticatable.rb": "module Authenticatable\n  extend ActiveSupport::Concern\n  included do\n    before_action :authenticate_user\n  end\n  def authenticate_user\n    @user = User.find_by(token: session[:u]) if session[:u]\n    true\n  end\nend\n"},
				usersCtl("ApplicationController", "")), []string{"DELETE /users/:id"}},
		{"a callback not named for it that answers 401 is the gate, one that raises is not", delRoute,
			with(map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::API", "  before_action :ensure_access_token\n  before_action :set_resource\n  def ensure_access_token\n    @token = Token.find_by(value: request.headers['X-Key'])\n  end\n  def set_resource\n    raise 'Overwrite this method'\n  end\n")},
				usersCtl("ApplicationController", "")), []string{"DELETE /users/:id"}},
		{"admin path on a GET", "  get '/admin/report', to: 'reports#show'\n", map[string]string{"reports_controller.rb": rbCtl("ReportsController", "ActionController::Base", "  def show\n  end\n")}, []string{"GET /admin/report"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, railsApp(c.routes, c.ctrls))
			if got := authnLeads(a); !slices.Equal(got, c.want) {
				t.Fatalf("leads = %v, want %v (routes %v)", got, c.want, routeKeys(a))
			}
		})
	}
}

// The safe variants: each shows access control, or hides it from this reader.
func TestRailsSafeVariantsAreNotLeads(t *testing.T) {
	appWith := func(body string) map[string]string {
		return map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::Base", body)}
	}
	merge := func(ms ...map[string]string) map[string]string {
		out := map[string]string{}
		for _, m := range ms {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}
	cases := map[string]struct {
		routes string
		ctrls  map[string]string
	}{
		"devise before_action on the controller":  {delRoute, merge(appWith(""), usersCtl("ApplicationController", "  before_action :authenticate_user!\n"))},
		"authn-named callback":                    {delRoute, merge(appWith(""), usersCtl("ApplicationController", "  before_action :require_login\n"))},
		"legacy before_filter":                    {delRoute, merge(appWith(""), usersCtl("ApplicationController", "  before_filter :authenticate_user!\n"))},
		"prepend_before_action":                   {delRoute, merge(appWith(""), usersCtl("ApplicationController", "  prepend_before_action :authenticate_user!\n"))},
		"only names this action":                  {delRoute, merge(appWith(""), usersCtl("ApplicationController", "  before_action :authenticate_user!, only: [:destroy]\n"))},
		"only with %i":                            {delRoute, merge(appWith(""), usersCtl("ApplicationController", "  before_action :authenticate_user!, only: %i[update destroy]\n"))},
		"except lists other actions":              {delRoute, merge(appWith(""), usersCtl("ApplicationController", "  before_action :authenticate_user!, except: [:index, :show]\n"))},
		"several names in one call":               {delRoute, merge(appWith(""), usersCtl("ApplicationController", "  before_action :set_user, :authenticate_user!\n"))},
		"admin check":                             {delRoute, merge(appWith(""), usersCtl("ApplicationController", "  before_action :require_admin\n"))},
		"cancan":                                  {delRoute, merge(appWith(""), usersCtl("ApplicationController", "  load_and_authorize_resource\n"))},
		"http basic":                              {delRoute, merge(appWith(""), usersCtl("ApplicationController", "  http_basic_authenticate_with name: 'a', password: 'b'\n"))},
		"inherited from ApplicationController":    {delRoute, merge(appWith("  before_action :authenticate_user!\n"), usersCtl("ApplicationController", ""))},
		"inherited through an intermediate class": {delRoute, merge(appWith(""), map[string]string{"base_controller.rb": rbCtl("BaseController", "ApplicationController", "  before_action :authenticate_user!\n")}, usersCtl("BaseController", ""))},
		"inherited, skipped for another action":   {delRoute, merge(appWith("  before_action :authenticate_user!\n"), usersCtl("ApplicationController", "  skip_before_action :authenticate_user!, only: [:index]\n"))},
		"module-qualified superclass":             {delRoute, merge(appWith(""), map[string]string{"admin/base_controller.rb": rbCtl("Admin::BaseController", "ApplicationController", "  before_action :authenticate_admin!\n")}, map[string]string{"users_controller.rb": rbCtl("UsersController", "Admin::BaseController", usersDestroy)})},
		"nested module class":                     {"  namespace :admin do\n    delete 'users/:id', to: 'users#destroy'\n  end\n", merge(appWith(""), map[string]string{"admin/base_controller.rb": "module Admin\n  class BaseController < ApplicationController\n    before_action :authenticate_admin!\n  end\nend\n", "admin/users_controller.rb": "module Admin\n  class UsersController < BaseController\n" + usersDestroy + "  end\nend\n"})},
		"devise authenticate block in routes":     {"  authenticate :user do\n    delete '/users/:id', to: 'users#destroy'\n  end\n", merge(appWith(""), usersCtl("ApplicationController", ""))},
		"authenticated block in routes":           {"  authenticated :user do\n    delete '/users/:id', to: 'users#destroy'\n  end\n", merge(appWith(""), usersCtl("ApplicationController", ""))},
		"authenticate block with a lambda":        {"  authenticate :user, ->(u) { u.admin? } do\n    delete '/users/:id', to: 'users#destroy'\n  end\n", merge(appWith(""), usersCtl("ApplicationController", ""))},
		"authenticate block around resources":     {"  authenticate :user do\n    resources :users\n  end\n", merge(appWith(""), usersCtl("ApplicationController", ""))},
		"inline check on the caller":              {delRoute, merge(appWith(""), map[string]string{"users_controller.rb": rbCtl("UsersController", "ApplicationController", "  def destroy\n    return head(:unauthorized) unless current_user\n    User.find(params[:id]).destroy\n  end\n")})},
		"inline 403 on an ownership check":        {delRoute, merge(appWith(""), map[string]string{"users_controller.rb": rbCtl("UsersController", "ApplicationController", "  def destroy\n    return head :forbidden unless params[:id] == session_id\n  end\n")})},
		"inline authenticate call":                {delRoute, merge(appWith(""), map[string]string{"users_controller.rb": rbCtl("UsersController", "ApplicationController", "  def destroy\n    authenticate_user!\n  end\n")})},
		"rails 8 concern":                         {delRoute, merge(map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::Base", "  include Authentication\n"), "concerns/authentication.rb": "module Authentication\n  extend ActiveSupport::Concern\n  included do\n    before_action :require_authentication\n  end\nend\n"}, usersCtl("ApplicationController", ""))},
		"a callback that redirects does authenticate": {delRoute, merge(map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::Base", "  include Authenticatable\n"),
			"concerns/authenticatable.rb": "module Authenticatable\n  extend ActiveSupport::Concern\n  included do\n    before_action :require_logged_in_user\n  end\n  def require_logged_in_user\n    redirect_to '/login' unless session[:u]\n  end\nend\n"}, usersCtl("ApplicationController", ""))},
		"a callback that reaches a redirect through another method": {delRoute, merge(map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::Base", "  before_action :require_authentication\n  def require_authentication\n    resume_session || request_authentication\n  end\n  def request_authentication\n    redirect_to new_session_path\n  end\n")}, usersCtl("ApplicationController", ""))},
		"a callback not named for it renders 401":                   {delRoute, merge(map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::API", "  before_action :ensure_access_token\n  before_action :set_platform_app\n  def ensure_access_token\n    @token = Token.find_by(value: request.headers['X-Key'])\n  end\n  def set_platform_app\n    render json: { error: 'Invalid' }, status: :unauthorized if @token.blank?\n  end\n")}, usersCtl("ApplicationController", ""))},
		"a conditional callback that renders 401 is not claimed":    {delRoute, merge(map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::API", "  before_action :gate, if: :api?\n  def gate\n    head :unauthorized\n  end\n")}, usersCtl("ApplicationController", ""))},
		"controller of a gem is not seen":                           {delRoute, merge(appWith(""), map[string]string{"users_controller.rb": rbCtl("UsersController", "Doorkeeper::ApplicationController", usersDestroy)})},
		"controller not in the repository":                          {delRoute, merge(appWith(""), nil)},
		"conditional callback is not claimed":                       {delRoute, merge(appWith(""), usersCtl("ApplicationController", "  before_action :authenticate_user!, unless: :api?\n"))},
		"conditional skip is not claimed public":                    {delRoute, merge(appWith("  before_action :authenticate_user!\n"), usersCtl("ApplicationController", "  skip_before_action :authenticate_user!, if: :api?\n"))},
		"constraint lambda may be a guard":                          {"  constraints(->(req) { req.session[:uid] }) do\n    delete '/users/:id', to: 'users#destroy'\n  end\n", merge(appWith(""), usersCtl("ApplicationController", ""))},
		"engine routes have no mount prefix":                        {"", nil},
		"unresolved concern with an authn name":                     {delRoute, merge(map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::Base", "  include Authenticatable\n")}, usersCtl("ApplicationController", ""))},
		"callback in a block":                                       {delRoute, merge(appWith(""), usersCtl("ApplicationController", "  before_action do\n    authenticate_user!\n  end\n"))},
		"login controller is public by design":                      {"  post '/login', to: 'sessions#create'\n  delete '/session', to: 'sessions#destroy'\n", merge(appWith(""), map[string]string{"sessions_controller.rb": rbCtl("SessionsController", "ApplicationController", "")})},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			files := railsApp(c.routes, c.ctrls)
			if name == "engine routes have no mount prefix" {
				files = map[string]string{
					"engines/x/config/routes.rb":                    "X::Engine.routes.draw do\n" + delRoute + "end\n",
					"engines/x/app/controllers/users_controller.rb": rbCtl("UsersController", "ActionController::Base", usersDestroy),
				}
			}
			a, _ := scanFiles(t, files)
			if len(a.Routes()) == 0 {
				t.Fatalf("no routes read; the test would pass for the wrong reason")
			}
			if got := authnLeads(a); len(got) != 0 {
				t.Fatalf("leads = %v, want none (routes %v)", got, routeKeys(a))
			}
		})
	}
}

// A route to an action nothing defines answers 404: `resources :tutorials` over
// a controller with two actions is not eight reachable endpoints.
func TestRailsRouteToAnUndefinedActionIsNotALead(t *testing.T) {
	appCtl := map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::Base", "")}
	ctl := func(super, body string) map[string]string {
		return map[string]string{"application_controller.rb": appCtl["application_controller.rb"], "users_controller.rb": rbCtl("UsersController", super, body)}
	}
	cases := []struct {
		name  string
		ctrls map[string]string
		want  []string
	}{
		{"defined", ctl("ApplicationController", "  def destroy; end\n  def update; end\n"), []string{"DELETE /users/:id", "PATCH /users/:id", "PUT /users/:id"}},
		{"only destroy defined", ctl("ApplicationController", "  def destroy; end\n"), []string{"DELETE /users/:id"}},
		{"nothing defined", ctl("ApplicationController", "  def index; end\n"), nil},
		{"defined in a concern", map[string]string{"application_controller.rb": appCtl["application_controller.rb"], "concerns/crud.rb": "module Crud\n  def destroy; end\n  def update; end\nend\n", "users_controller.rb": rbCtl("UsersController", "ApplicationController", "  include Crud\n")}, []string{"DELETE /users/:id", "PATCH /users/:id", "PUT /users/:id"}},
		{"an include this reader cannot read may define it", ctl("ApplicationController", "  include Gem::Crud\n"), []string{"DELETE /users/:id", "PATCH /users/:id", "PUT /users/:id"}},
		{"defined at run time", ctl("ApplicationController", "  define_method(:destroy) { }\n"), []string{"DELETE /users/:id", "PATCH /users/:id", "PUT /users/:id"}},
		{"inherited", map[string]string{"application_controller.rb": rbCtl("ApplicationController", "ActionController::Base", "  def destroy; end\n  def update; end\n"), "users_controller.rb": rbCtl("UsersController", "ApplicationController", "")}, []string{"DELETE /users/:id", "PATCH /users/:id", "PUT /users/:id"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, railsApp("  resources :users, only: [:update, :destroy]\n", c.ctrls))
			if got := authnLeads(a); !slices.Equal(got, c.want) {
				t.Fatalf("leads = %v, want %v", got, c.want)
			}
		})
	}
}

func TestRailsParamOptionNamesTheSegment(t *testing.T) {
	a, _ := scanFiles(t, railsApp("  resources :profiles, param: :username, only: [:show] do\n    resource :follow, only: [:destroy]\n  end\n", nil))
	if got := routeKeys(a); !slices.Equal(got, []string{"DELETE /profiles/:profile_username/follow", "GET /profiles/:username"}) {
		t.Fatalf("routes = %v", got)
	}
}

func TestRailsRecordsAuthenticationOnRoutes(t *testing.T) {
	files := railsApp(delRoute+"  get '/pub', to: 'pub#show'\n", map[string]string{
		"application_controller.rb": rbCtl("ApplicationController", "ActionController::Base", "  before_action :authenticate_user!\n"),
		"users_controller.rb":       rbCtl("UsersController", "ApplicationController", usersDestroy),
		"pub_controller.rb":         rbCtl("PubController", "ApplicationController", "  skip_before_action :authenticate_user!\n  def show\n  end\n"),
	})
	a, _ := scanFiles(t, files)
	if got, ok := routeAuthn(a, "DELETE /users/:id"); !ok || got != "before_action :authenticate_user!" {
		t.Errorf("users#destroy Authn = %q (found %v)", got, ok)
	}
	if got, ok := routeAuthn(a, "GET /pub"); !ok || got != "" {
		t.Errorf("pub#show Authn = %q (found %v)", got, ok)
	}
}

// A skipped authentication callback is the code saying the action is open. For a
// state-changing route that is exactly what a reviewer should look at, so it
// stays a lead; only public-by-design paths stay quiet.
func TestRailsSkippedAuthenticationStaysAReviewableLead(t *testing.T) {
	files := railsApp(delRoute+"  post '/sessions', to: 'users#create'\n", map[string]string{
		"application_controller.rb": rbCtl("ApplicationController", "ActionController::Base", "  before_action :authenticate_user!\n"),
		"users_controller.rb":       rbCtl("UsersController", "ApplicationController", "  skip_before_action :authenticate_user!\n"+usersDestroy),
	})
	a, _ := scanFiles(t, files)
	if got := authnLeads(a); !slices.Equal(got, []string{"DELETE /users/:id"}) {
		t.Fatalf("leads = %v", got)
	}
}

func TestRailsDrawnFilesInheritTheirDrawSite(t *testing.T) {
	files := map[string]string{
		"config/routes.rb":                          "Rails.application.routes.draw do\n  namespace :admin do\n    draw :users\n  end\nend\n",
		"config/routes/users.rb":                    "delete 'users/:id', to: 'users#destroy'\n",
		"config/routes/orphan.rb":                   "delete 'orphans/:id', to: 'orphans#destroy'\n",
		"app/controllers/admin/users_controller.rb": rbCtl("Admin::UsersController", "ActionController::Base", usersDestroy),
	}
	a, _ := scanFiles(t, files)
	if got := routeKeys(a); !slices.Equal(got, []string{"DELETE /admin/users/:id"}) {
		t.Fatalf("routes = %v", got)
	}
	if got := authnLeads(a); !slices.Equal(got, []string{"DELETE /admin/users/:id"}) {
		t.Fatalf("leads = %v", got)
	}
}

func TestRailsOnlyReadsRoutesFiles(t *testing.T) {
	files := map[string]string{
		"spec/config/routes.rb":    "Rails.application.routes.draw do\n  delete '/users/:id', to: 'users#destroy'\nend\n",
		"lib/something/routing.rb": "Rails.application.routes.draw do\n  delete '/x/:id', to: 'x#destroy'\nend\n",
	}
	a, _ := scanFiles(t, files)
	if got := routeKeys(a); !slices.Equal(got, []string{"DELETE /users/:id"}) {
		t.Fatalf("routes = %v", got)
	}
	if got := authnLeads(a); len(got) != 0 {
		t.Fatalf("a spec tree's route is a lead: %v", got)
	}
}
