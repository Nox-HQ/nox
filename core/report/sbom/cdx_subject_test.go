package sbom

import (
	"encoding/json"
	"testing"
)

// A CycloneDX BOM of a release artifact describes that artifact, as the SPDX
// one does: metadata.component names it with its SHA-256, it depends on every
// listed component, and the serial number derives from its digest, so the same
// file gets the same serial and different files different ones.
func TestCDXSubjectIsTheDescribedArtifact(t *testing.T) {
	const sum = "43a33d809955b1c6c5e9e09553a82e87ac11a4337f2640183dfa65795117d344"
	gen := func(name, digest string) CDXReport {
		data, err := NewCycloneDXReporter("1.0.0").WithSubject(name, digest).Generate(testInventory())
		if err != nil {
			t.Fatal(err)
		}
		var doc CDXReport
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	doc := gen("nox_1.0.0_darwin_arm64.tar.gz", sum)

	c := doc.Metadata.Component
	if c == nil {
		t.Fatal("no metadata.component for the artifact")
	}
	if c.Name != "nox_1.0.0_darwin_arm64.tar.gz" || c.Type != "file" {
		t.Errorf("subject %+v, want the artifact as a file", c)
	}
	if len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-256" || c.Hashes[0].Content != sum {
		t.Errorf("subject hashes %+v, want SHA-256 %s", c.Hashes, sum)
	}
	if len(doc.Dependencies) != 1 || doc.Dependencies[0].Ref != c.BOMRef {
		t.Fatalf("dependencies %+v, want one entry for the subject %q", doc.Dependencies, c.BOMRef)
	}
	if got, want := len(doc.Dependencies[0].DependsOn), len(testInventory().Packages()); got != want {
		t.Errorf("subject depends on %d components, want %d", got, want)
	}
	if !uuidURN.MatchString(doc.SerialNumber) {
		t.Errorf("serial %q is not a UUID URN", doc.SerialNumber)
	}
	if again := gen("nox_1.0.0_darwin_arm64.tar.gz", sum); again.SerialNumber != doc.SerialNumber {
		t.Error("the same artifact got two serials")
	}
	other := gen("nox_1.0.0_linux_amd64.tar.gz", "0000000000000000000000000000000000000000000000000000000000000001")
	if other.SerialNumber == doc.SerialNumber {
		t.Error("two artifacts with the same packages share a serial")
	}
}

// Without a subject the document is a scan's, as before: no metadata.component
// and no dependencies.
func TestCDXWithoutSubjectIsUnchanged(t *testing.T) {
	data, err := NewCycloneDXReporter("1.0.0").Generate(testInventory())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(data, &doc)
	if _, ok := doc["dependencies"]; ok {
		t.Error("a scan BOM grew a dependencies section")
	}
	if _, ok := doc["metadata"].(map[string]any)["component"]; ok {
		t.Error("a scan BOM grew a metadata.component")
	}
}
