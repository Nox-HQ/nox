package core

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

const axiosLock = `{"name":"app","lockfileVersion":3,"packages":{"":{"dependencies":{"axios":"0.21.1","express":"4.17.1"}},` +
	`"node_modules/axios":{"version":"0.21.1"},"node_modules/express":{"version":"4.17.1"}}}`

func axiosFinding(t *testing.T, files map[string]string) findings.Finding {
	t.Helper()
	osv := newOSVDouble(t, map[string]string{"axios@0.21.1": "GHSA-test-axios"})
	files["package.json"] = `{"dependencies":{"axios":"0.21.1","express":"4.17.1"}}`
	files["package-lock.json"] = axiosLock
	files[".nox.yaml"] = osvConfig(osv.srv.URL)
	res, err := RunScanWithOptions(writeNPMProject(t, files), ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings.Findings() {
		if f.RuleID == "VULN-001" && f.Metadata["package"] == "axios" {
			return f
		}
	}
	t.Fatalf("no VULN-001 for axios; findings: %v", res.Findings.Findings())
	return findings.Finding{}
}

// A dependency used to stop at "the project imports it" in every ecosystem but
// Go. The source call graph climbs it to call_reachable when code that runs
// calls into it, with the path as the witness.
func TestDependencyCallReachableThroughARoute(t *testing.T) {
	reached := axiosFinding(t, map[string]string{
		"server.js": "const express = require('express');\nconst axios = require('axios');\nconst app = express();\n\n" +
			"function fetchUpstream(u) {\n  return axios.get(u);\n}\n\n" +
			"app.get('/proxy', (req, res) => {\n  fetchUpstream(req.query.url);\n});\n\napp.listen(3000);\n",
	})
	m := reached.Metadata
	if m["applicability_reached"] != "call_reachable" || m["applicability"] != "impacting" {
		t.Fatalf("applicability = %s/%s, want impacting/call_reachable; metadata %v", m["applicability"], m["applicability_reached"], m)
	}
	if m["entry_kind"] != "route" || !strings.Contains(m["entry_reason"], "/proxy") {
		t.Errorf("entry = %q (%q), want the /proxy route handler", m["entry_kind"], m["entry_reason"])
	}
	if want := "server.js:<anonymous>@9 -> server.js:fetchUpstream"; m["call_path"] != want {
		t.Errorf("call_path = %q, want %q", m["call_path"], want)
	}
	if _, stopped := m["applicability_stopped_at"]; stopped {
		t.Errorf("a climbed verdict still says where it stopped: %v", m)
	}
	if !strings.Contains(reached.Message, "HTTP route") || strings.Count(reached.Message, " — ") != 1 {
		t.Errorf("message = %q", reached.Message)
	}

	// The same advisory, imported and never called: the analyzer's verdict,
	// so the same fingerprint. The climb must not move it, or every baseline
	// and VEX statement written before it would stop applying.
	importedOnly := axiosFinding(t, map[string]string{
		"server.js": "const axios = require('axios');\nmodule.exports = { client: axios };\n",
	})
	if importedOnly.Metadata["applicability_reached"] == "call_reachable" {
		t.Errorf("an import nothing calls climbed: %v", importedOnly.Metadata)
	}
	if reached.Fingerprint != importedOnly.Fingerprint {
		t.Errorf("fingerprint moved with the climb: %s vs %s", reached.Fingerprint, importedOnly.Fingerprint)
	}
}

func TestDependencyDoesNotClimbWithoutAPathFromAnEntry(t *testing.T) {
	tests := map[string]map[string]string{
		// Only the test suite calls it.
		"called from tests only": {
			"lib.js":           "const axios = require('axios');\nexport function get(u) {\n  return axios.get(u);\n}\n",
			"test/lib.test.js": "import { get } from '../lib';\nit('gets', () => {\n  get('x');\n});\n",
		},
		// A local named like the package, and no import of it.
		"a local that shares the name": {
			"a.js": "const axios = { get() {} };\nfunction f() {\n  axios.get('x');\n}\nf();\n",
		},
	}
	for name, files := range tests {
		t.Run(name, func(t *testing.T) {
			f := axiosFinding(t, files)
			if f.Metadata["applicability_reached"] == "call_reachable" {
				t.Errorf("climbed to call_reachable: %v", f.Metadata)
			}
		})
	}
}

// A Rails app requires no gem by name: Bundler.require loads the Gemfile's
// gems at boot, and an action is reached only through config/routes.rb. Both
// have to be read for a gem advisory to climb.
func TestDependencyCallReachableInRails(t *testing.T) {
	scan := func(t *testing.T, gemfile string) findings.Finding {
		t.Helper()
		osv := newOSVDouble(t, map[string]string{"nokogiri@1.10.0": "GHSA-test-nokogiri"})
		dir := writeNPMProject(t, map[string]string{
			"Gemfile":               gemfile,
			"Gemfile.lock":          "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.10.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  nokogiri\n",
			"config/application.rb": "require_relative 'boot'\nrequire 'rails/all'\nBundler.require(*Rails.groups)\nmodule App\n  class Application < Rails::Application\n  end\nend\n",
			"config/routes.rb":      "Rails.application.routes.draw do\n  post 'import', to: 'documents#import'\nend\n",
			"app/controllers/documents_controller.rb": "class DocumentsController < ApplicationController\n  def import\n    doc = parse_xml(params[:xml])\n    render json: doc\n  end\n\n  private\n\n  def parse_xml(x)\n    Nokogiri::XML(x)\n  end\nend\n",
			".nox.yaml": osvConfig(osv.srv.URL),
		})
		res, err := RunScanWithOptions(dir, ScanOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range res.Findings.Findings() {
			if f.RuleID == "VULN-001" && f.Metadata["package"] == "nokogiri" {
				return f
			}
		}
		t.Fatalf("no VULN-001 for nokogiri")
		return findings.Finding{}
	}
	f := scan(t, "source 'https://rubygems.org'\ngem 'rails'\ngem 'nokogiri'\n")
	m := f.Metadata
	if m["applicability_reached"] != "call_reachable" || m["entry_kind"] != "route" {
		t.Fatalf("applicability %s from %s, want call_reachable from a route; %v", m["applicability_reached"], m["entry_kind"], m)
	}
	if want := "app/controllers/documents_controller.rb:import -> app/controllers/documents_controller.rb:parse_xml"; m["call_path"] != want {
		t.Errorf("call_path = %q, want %q", m["call_path"], want)
	}
	// The same gem only in the test group is not loaded in production.
	if g := scan(t, "source 'https://rubygems.org'\ngem 'rails'\ngroup :test do\n  gem 'nokogiri'\nend\n"); g.Metadata["applicability_reached"] == "call_reachable" {
		t.Errorf("a test-group gem climbed: %v", g.Metadata)
	}
}
