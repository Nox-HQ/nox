package sbom

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/deps"
)

var uuidURN = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// TestCDX_SerialNumberIsValidUUID guards the schema failure that made every
// CycloneDX document invalid: serialNumber was the constant "urn:uuid:nox-scan",
// which does not match the required UUID URN grammar.
func TestCDX_SerialNumberIsValidUUID(t *testing.T) {
	t.Parallel()

	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "x", Version: "1.0.0", Ecosystem: "npm"})

	doc := cdxDoc(t, inv)
	if serial := doc["serialNumber"].(string); !uuidURN.MatchString(serial) {
		t.Errorf("serialNumber %q is not a valid UUID URN", serial)
	}
}

// TestCDX_SerialNumberIsDeterministic keeps the fix compatible with nox's
// reproducible-output guarantee: identical input yields an identical serial.
func TestCDX_SerialNumberIsDeterministic(t *testing.T) {
	t.Parallel()

	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "x", Version: "1.0.0", Ecosystem: "npm"})
	if cdxDoc(t, inv)["serialNumber"] != cdxDoc(t, inv)["serialNumber"] {
		t.Error("serialNumber differs across identical scans")
	}
}

// TestCDX_NonSPDXLicenseGoesToName guards the schema failure where an arbitrary
// license string was placed in license.id, which CycloneDX validates against
// the SPDX enumeration.
func TestCDX_NonSPDXLicenseGoesToName(t *testing.T) {
	t.Parallel()

	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "spdx", Version: "1", Ecosystem: "npm", License: "MIT"})
	inv.Add(deps.Package{Name: "free", Version: "1", Ecosystem: "npm", License: "Apache 2.0"})

	for _, c := range cdxDoc(t, inv)["components"].([]any) {
		comp := c.(map[string]any)
		lic := comp["licenses"].([]any)[0].(map[string]any)["license"].(map[string]any)
		switch comp["name"] {
		case "spdx":
			if lic["id"] != "MIT" {
				t.Errorf("valid SPDX id should be in license.id, got %v", lic)
			}
		case "free":
			if _, has := lic["id"]; has {
				t.Errorf("non-SPDX %q must not be in license.id: %v", "Apache 2.0", lic)
			}
			if lic["name"] != "Apache 2.0" {
				t.Errorf("non-SPDX license should be in license.name, got %v", lic)
			}
		}
	}
}

func cdxDoc(t *testing.T, inv *deps.PackageInventory) map[string]any {
	t.Helper()
	out, err := (&CycloneDXReporter{}).Generate(inv)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("json: %v", err)
	}
	return doc
}
