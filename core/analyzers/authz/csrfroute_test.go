package authz

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func csrfRouteFindings(fs []findings.Finding) []string {
	var out []string
	for _, f := range fs {
		if f.RuleID == CSRFRouteRuleID {
			out = append(out, f.Metadata["route"])
		}
	}
	slices.Sort(out)
	return out
}

const flaskLoginHead = "from flask import Flask, request\nfrom flask_login import login_required, current_user\napp = Flask(__name__)\n"

const expressSessionHead = "const express = require('express');\nconst session = require('express-session');\nconst app = express();\napp.use(express.urlencoded({ extended: false }));\napp.use(session({ secret: process.env.S }));\n"

func TestUnprotectedSessionRoutes(t *testing.T) {
	flaskForm := "@app.route('/notes', methods=['POST'])\n@login_required\ndef add_note():\n    save(current_user.id, request.form['text'])\n    return 'ok'\n"
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"flask form post behind login", map[string]string{"app.py": flaskLoginHead + flaskForm},
			[]string{"POST /notes"}},
		{"flask post that reads no body", map[string]string{"app.py": flaskLoginHead + "@app.route('/notes/<int:id>/delete', methods=['POST'])\n@login_required\ndef delete_note(id):\n    remove(current_user.id, id)\n    return 'ok'\n"},
			[]string{"POST /notes/<int:id>/delete"}},
		{"express form post behind the session", map[string]string{"server.js": expressSessionHead + "app.post('/transfer', isLoggedIn, (req, res) => { move(req.session.user, req.body.amount); res.end(); });\n"},
			[]string{"POST /transfer"}},

		{"flask handler reads JSON and the form", map[string]string{"app.py": flaskLoginHead + "@app.post('/notes')\n@login_required\ndef add_note():\n    save(current_user.id, request.get_json(silent=True) or request.form)\n    return 'ok'\n"},
			[]string{"POST /notes"}},

		// Counterexamples.
		{"a public form in a session application", map[string]string{"app.py": flaskLoginHead + "@app.route('/contact', methods=['POST'])\ndef contact():\n    mail(request.form['text'])\n    return 'ok'\n"}, nil},
		{"Flask-WTF CSRFProtect", map[string]string{"app.py": flaskLoginHead + "from flask_wtf.csrf import CSRFProtect\nCSRFProtect(app)\n" + flaskForm}, nil},
		{"session cookie SameSite=Lax", map[string]string{"app.py": flaskLoginHead + "app.config.update(SESSION_COOKIE_SAMESITE='Lax')\n" + flaskForm}, nil},
		{"express session cookie sameSite strict", map[string]string{"server.js": "const express = require('express');\nconst session = require('express-session');\nconst app = express();\napp.use(express.urlencoded({ extended: false }));\napp.use(session({ secret: process.env.S, cookie: { sameSite: 'strict' } }));\napp.post('/transfer', isLoggedIn, (req, res) => { move(req.session.user, req.body.amount); res.end(); });\n"}, nil},
		{"csurf in express", map[string]string{"server.js": expressSessionHead + "const csrf = require('csurf');\napp.use(csrf());\napp.post('/transfer', isLoggedIn, (req, res) => { move(req.session.user, req.body.amount); res.end(); });\n"}, nil},
		{"flask handler reads only JSON", map[string]string{"app.py": flaskLoginHead + "@app.post('/notes')\n@login_required\ndef add_note():\n    save(current_user.id, request.get_json()['text'])\n    return 'ok'\n"}, nil},
		{"express with no form-body parser reads only JSON", map[string]string{"server.js": "const express = require('express');\nconst session = require('express-session');\nconst app = express();\napp.use(express.json());\napp.use(session({ secret: process.env.S }));\napp.post('/transfer', isLoggedIn, (req, res) => { move(req.session.user, req.body.amount); res.end(); });\n"}, nil},
		{"DELETE needs a preflight", map[string]string{"app.py": flaskLoginHead + "@app.route('/notes/<int:id>', methods=['DELETE'])\n@login_required\ndef delete_note(id):\n    remove(current_user.id, id)\n    return 'ok'\n"}, nil},
		{"token authentication", map[string]string{"app.py": flaskLoginHead + "from flask_jwt_extended import jwt_required\n@app.route('/notes', methods=['POST'])\n@jwt_required()\ndef add_note():\n    save(current_user.id, request.form['text'])\n    return 'ok'\n"}, nil},
		{"no cookie session in the application", map[string]string{"app.py": "from flask import Flask, request\napp = Flask(__name__)\n@app.route('/notes', methods=['POST'])\n@login_required\ndef add_note():\n    save(request.form['text'])\n    return 'ok'\n"}, nil},
		{"login writes the session, it is not reached with one", map[string]string{"app.py": flaskLoginHead + "from flask import session\n@app.route('/login', methods=['POST'])\ndef login():\n    session['user'] = request.form['u']\n    return 'ok'\n"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, fs := scanFiles(t, tc.files)
			if got := csrfRouteFindings(fs); !slices.Equal(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
