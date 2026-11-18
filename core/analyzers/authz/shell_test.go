package authz

import (
	"slices"
	"testing"
)

// A route that serves a single-page app's HTML shell is the same page for
// everyone; the data is behind the API routes, which stay leads.
func TestRailsSPAShellRoutesAreNotLeads(t *testing.T) {
	const shellRoutes = "  get '/app/*params', to: 'dashboard#index'\n" +
		"  get '/app/accounts/:account_id/settings/inboxes/:inbox_id', to: 'dashboard#index'\n" +
		"  get '/admin/*path', to: 'dashboard#index'\n" +
		"  get '*path', to: 'dashboard#index'\n"
	shellCtl := rbCtl("DashboardController", "ActionController::Base", "  layout 'vueapp'\n  def index; end\n")
	cases := []struct {
		name   string
		routes string
		ctrls  map[string]string
		want   []string
	}{
		{"empty action behind a catch-all", shellRoutes, map[string]string{"dashboard_controller.rb": shellCtl}, nil},
		{"multi-line empty action", shellRoutes, map[string]string{"dashboard_controller.rb": rbCtl("DashboardController", "ActionController::Base", "  def index\n  end\n")}, nil},
		{"callbacks that do not read params", shellRoutes, map[string]string{"dashboard_controller.rb": rbCtl("DashboardController", "ActionController::Base",
			"  before_action :set_config\n  def index; end\n  private\n  def set_config\n    @config = GlobalConfig.get('X')\n  end\n")}, nil},

		// True-positive twins: each of these still fires.
		{"the action loads a record", shellRoutes, map[string]string{"dashboard_controller.rb": rbCtl("DashboardController", "ActionController::Base",
			"  def index\n    @account = Account.find(params[:account_id])\n  end\n")},
			[]string{"GET /admin/*path", "GET /app/accounts/:account_id/settings/inboxes/:inbox_id"}},
		{"a callback loads a record from params", shellRoutes, map[string]string{"dashboard_controller.rb": rbCtl("DashboardController", "ActionController::Base",
			"  before_action :set_account\n  def index; end\n  private\n  def set_account\n    @account = Account.find(params[:account_id])\n  end\n")},
			[]string{"GET /admin/*path", "GET /app/accounts/:account_id/settings/inboxes/:inbox_id"}},
		{"no catch-all: a specific route to an empty action is still read", "  get '/app/accounts/:account_id/settings/inboxes/:inbox_id', to: 'dashboard#index'\n",
			map[string]string{"dashboard_controller.rb": shellCtl},
			[]string{"GET /app/accounts/:account_id/settings/inboxes/:inbox_id"}},
		{"a catch-all under another prefix does not cover the route", "  get '/docs/*path', to: 'dashboard#index'\n  get '/app/accounts/:account_id/settings/inboxes/:inbox_id', to: 'dashboard#index'\n",
			map[string]string{"dashboard_controller.rb": shellCtl},
			[]string{"GET /app/accounts/:account_id/settings/inboxes/:inbox_id"}},
		{"a catch-all to a different action does not cover the route", "  get '/app/*params', to: 'dashboard#index'\n  get '/app/accounts/:account_id/settings/inboxes/:inbox_id', to: 'dashboard#show'\n",
			map[string]string{"dashboard_controller.rb": rbCtl("DashboardController", "ActionController::Base", "  def index; end\n  def show\n    @a = Account.find(params[:account_id])\n  end\n")},
			[]string{"GET /app/accounts/:account_id/settings/inboxes/:inbox_id"}},
		{"a controller that includes a concern the repository does not have", shellRoutes, map[string]string{"dashboard_controller.rb": rbCtl("DashboardController", "ActionController::Base",
			"  include Trackable\n  def index; end\n")},
			[]string{"GET /admin/*path", "GET /app/accounts/:account_id/settings/inboxes/:inbox_id"}},
		{"only a non-GET catch-all exists", "  post '/admin/*path', to: 'dashboard#index'\n  get '/admin/users/:id', to: 'dashboard#index'\n",
			map[string]string{"dashboard_controller.rb": shellCtl},
			[]string{"GET /admin/users/:id", "POST /admin/*path"}},
		{"a mutating catch-all is not the shell", "  put '/admin/*path', to: 'dashboard#index'\n  get '/admin/*path', to: 'dashboard#index'\n  put '/admin/users/:id', to: 'dashboard#index'\n",
			map[string]string{"dashboard_controller.rb": shellCtl},
			[]string{"PUT /admin/*path", "PUT /admin/users/:id"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, railsApp(c.routes, c.ctrls))
			if got := authnLeads(a); !slices.Equal(got, c.want) {
				t.Fatalf("leads = %v, want %v", got, c.want)
			}
		})
	}
}

func TestExpressSPAShellRoutesAreNotLeads(t *testing.T) {
	const head = "const express = require('express');\nconst path = require('path');\nconst app = express();\n"
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"catch-all sendFile of index.html", `app.get('/admin/*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});
app.get('/accounts/:id/settings', (req, res) => res.sendFile(path.join(__dirname, 'dist/index.html')));`, nil},
		{"function expression", `app.get('/admin/*', function (req, res) { return res.sendFile(path.resolve(__dirname, 'index.html')); });`, nil},

		// True-positive twins.
		{"the file name comes from the request", `app.get('/admin/*', (req, res) => res.sendFile(path.join(__dirname, 'dist', req.params[0] + '.html')));`,
			[]string{"GET /admin/*"}},
		{"the handler does more than send the file", `app.get('/admin/*', (req, res) => {
  audit(req);
  res.sendFile(path.join(__dirname, 'index.html'));
});`, []string{"GET /admin/*"}},
		{"the file is not html", `app.get('/admin/*', (req, res) => res.sendFile(path.join(__dirname, 'secrets.json')));`,
			[]string{"GET /admin/*"}},
		{"a PUT that sends the file is still a mutating route", `app.put('/admin/*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));`,
			[]string{"PUT /admin/*"}},
		{"a data handler", `app.get('/accounts/:id/settings', (req, res) => res.json(db.settings(req.params.id)));`,
			[]string{"GET /accounts/:id/settings"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, map[string]string{"server.js": head + c.body + "\napp.listen(3000);\n"})
			if got := authnLeads(a); !slices.Equal(got, c.want) {
				t.Fatalf("leads = %v, want %v", got, c.want)
			}
		})
	}
}
