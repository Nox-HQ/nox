package intel

import (
	"strings"
	"testing"
)

func TestBuildServiceInventory(t *testing.T) {
	pkgs := []Package{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}, // found in two manifests
		{Ecosystem: "npm", Name: "express", Version: "4.18.2"},
		{Ecosystem: "npm", Name: "", Version: "1.0.0"}, // unusable
	}
	imports := func(eco, name string) bool { return eco == "npm" && name == "lodash" }
	sites := []SinkSite{
		{Class: "command_injection", Call: "child_process.exec", File: "b.js", Line: 9},
		{Class: "command_injection", Call: "child_process.exec", File: "a.js", Line: 3},
		{Class: "xss", Call: "res.send", File: "a.js", Line: 5},
	}
	inv, err := BuildServiceInventory(pkgs, imports, sites, InventoryOptions{
		Service: "checkout", Exposed: true,
		Capabilities: []string{"secret.read"}, DataClasses: []string{"payment", "payment"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Components) != 2 {
		t.Fatalf("components %+v, want lodash and express once each", inv.Components)
	}
	byPkg := map[string]Component{}
	for _, c := range inv.Components {
		byPkg[c.Package] = c
		if !ValidComponentID(c.ID) || c.Service != "checkout" {
			t.Errorf("component %+v", c)
		}
	}
	if l := byPkg["lodash"]; !l.VulnerablePathReachable || !l.ExternallyExposed {
		t.Errorf("imported lodash in an exposed service: %+v", l)
	}
	// Exposure is declared for the service, and only reaches what its code uses.
	if e := byPkg["express"]; e.VulnerablePathReachable || e.ExternallyExposed {
		t.Errorf("express is not imported and must not be reachable or exposed: %+v", e)
	}
	if got := strings.Join(byPkg["express"].Capabilities, ","); got != "secret.read,shell.execute" {
		t.Errorf("capabilities %q: every component holds what the process holds", got)
	}
	if got := strings.Join(byPkg["lodash"].DataClasses, ","); got != "payment" {
		t.Errorf("data classes %q", got)
	}
	// One derived capability per authority, citing the first site; xss grants none.
	if len(inv.Derived) != 1 || inv.Derived[0].Capability != "shell.execute" ||
		inv.Derived[0].Evidence.File != "a.js" || inv.Derived[0].Evidence.Line != 3 {
		t.Errorf("derived %+v", inv.Derived)
	}
}

func TestComponentIDsAreStableAndDistinct(t *testing.T) {
	a := componentID("svc", Package{Ecosystem: "npm", Name: "@types/node", Version: "20.1.0"})
	b := componentID("svc", Package{Ecosystem: "npm", Name: "_types_node", Version: "20.1.0"})
	if a == b {
		t.Errorf("packages that sanitise alike share id %q", a)
	}
	if a != componentID("svc", Package{Ecosystem: "npm", Name: "@types/node", Version: "20.1.0"}) {
		t.Error("id is not stable")
	}
	if b != "svc:npm:_types_node@20.1.0" {
		t.Errorf("an id needing no change should read as written, got %q", b)
	}
	long := componentID("svc", Package{Ecosystem: "go", Name: "github.com/" + strings.Repeat("x", 200), Version: "v1.0.0"})
	if !ValidComponentID(long) {
		t.Errorf("long id %q is not acceptable to the service", long)
	}
}

func TestBuildServiceInventoryRefusesWhatTheServiceWould(t *testing.T) {
	for name, opts := range map[string]InventoryOptions{
		"service with a slash": {Service: "team/checkout"},
		"empty service":        {Service: ""},
		"capability not slug":  {Service: "s", Capabilities: []string{"root"}},
		"blank identity":       {Service: "s", Identities: []string{" "}},
	} {
		if _, err := BuildServiceInventory(nil, nil, nil, opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestServiceNameFrom(t *testing.T) {
	for in, want := range map[string]string{
		"checkout-api": "checkout-api",
		"my service":   "my_service",
		".hidden":      "hidden",
		"...":          "service",
	} {
		if got := ServiceNameFrom(in); got != want || !ValidServiceName(got) {
			t.Errorf("ServiceNameFrom(%q) = %q, want %q", in, got, want)
		}
	}
}
