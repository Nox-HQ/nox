package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/deps"
)

func spdxOf(t *testing.T, r *SPDXReporter, inv *deps.PackageInventory) SPDXDocument {
	t.Helper()
	data, err := r.Generate(inv)
	if err != nil {
		t.Fatal(err)
	}
	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// SPDX 2.3 requires each document's namespace to be unique. nox wrote one
// constant URI for every SBOM it ever produced. The namespace is now derived
// from the content, so different inventories get different namespaces and the
// same inventory the same one (nox's output stays deterministic).
func TestSPDXNamespaceIsUniquePerContentAndDeterministic(t *testing.T) {
	one := &deps.PackageInventory{}
	one.Add(deps.Package{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"})
	two := &deps.PackageInventory{}
	two.Add(deps.Package{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"})

	a := spdxOf(t, NewSPDXReporter("1.0.0"), one).DocumentNamespace
	again := spdxOf(t, NewSPDXReporter("1.0.0"), one).DocumentNamespace
	b := spdxOf(t, NewSPDXReporter("1.0.0"), two).DocumentNamespace
	if a == b {
		t.Errorf("two different inventories share the namespace %s", a)
	}
	if a != again {
		t.Errorf("the same inventory got two namespaces: %s, %s", a, again)
	}
	if !strings.HasPrefix(a, "https://") {
		t.Errorf("namespace %q is not an absolute URI", a)
	}
}

// An SBOM of a release artifact names the artifact and carries its checksum,
// so a reader can tell which file it describes: the document describes the
// artifact, and the artifact contains each package.
func TestSPDXSubjectIsTheDescribedArtifact(t *testing.T) {
	const sum = "43a33d809955b1c6c5e9e09553a82e87ac11a4337f2640183dfa65795117d344"
	doc := spdxOf(t, NewSPDXReporter("1.0.0").WithSubject("nox_1.0.0_darwin_arm64.tar.gz", sum), testInventory())

	if doc.Name != "nox_1.0.0_darwin_arm64.tar.gz" {
		t.Errorf("document name %q, want the artifact", doc.Name)
	}
	var subject *SPDXPackage
	for i := range doc.Packages {
		if doc.Packages[i].SPDXID == spdxSubjectID {
			subject = &doc.Packages[i]
		}
	}
	if subject == nil {
		t.Fatal("no package for the artifact itself")
	}
	if len(subject.Checksums) != 1 || subject.Checksums[0].Algorithm != "SHA256" || subject.Checksums[0].ChecksumValue != sum {
		t.Errorf("artifact checksums %+v, want SHA256 %s", subject.Checksums, sum)
	}
	describes, contains := 0, 0
	for _, r := range doc.Relationships {
		switch {
		case r.SPDXElementID == "SPDXRef-DOCUMENT" && r.RelationshipType == "DESCRIBES":
			describes++
			if r.RelatedSPDXElement != spdxSubjectID {
				t.Errorf("the document describes %s, not the artifact", r.RelatedSPDXElement)
			}
		case r.SPDXElementID == spdxSubjectID && r.RelationshipType == "CONTAINS":
			contains++
		}
	}
	if describes != 1 || contains != len(testInventory().Packages()) {
		t.Errorf("DESCRIBES %d (want 1), CONTAINS %d (want one per package)", describes, contains)
	}
	if !strings.Contains(doc.DocumentNamespace, sum) {
		t.Errorf("namespace %q does not identify the artifact", doc.DocumentNamespace)
	}
}
