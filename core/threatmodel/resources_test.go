package threatmodel

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/infra"
	"github.com/nox-hq/nox/core/report"
)

var cwe284 = map[string]string{"cwe": "CWE-284"}

func hardenedInventory() *infra.Inventory {
	inv := &infra.Inventory{Resources: []infra.Resource{
		{Kind: "aws_s3_bucket", Name: "invoices", File: "deploy/tf/main.tf", Class: infra.ClassBucket, Line: 1, EndLine: 3,
			Properties: map[string]string{"public_access_block": "all true", "acl": "private"}},
		{Kind: "aws_db_instance", Name: "main", File: "deploy/tf/main.tf", Class: infra.ClassDatabase, Line: 20, EndLine: 26,
			Properties: map[string]string{"publicly_accessible": "false", "storage_encrypted": "true"}},
		{Kind: "aws_security_group", Name: "db", File: "deploy/tf/main.tf", Class: infra.ClassNetworkRule, Line: 12, EndLine: 18,
			Properties: map[string]string{"open_to_world": "false"}},
		{Kind: "Ingress", Name: "invoicely", File: "deploy/k8s/ingress.yaml", Class: infra.ClassIngress, Line: 1, EndLine: 12,
			Properties: map[string]string{"tls": "all hosts", "ssl_redirect": "true"}},
		{Kind: "Deployment", Name: "invoicely", File: "deploy/k8s/deployment.yaml", Class: infra.ClassWorkload, Line: 1, EndLine: 30,
			Properties: map[string]string{"privileged": "false", "run_as_user": "10001", "env.DATABASE_PASSWORD": "secretKeyRef"}},
	}}
	inv.Normalize()
	return inv
}

func weakenedInventory() *infra.Inventory {
	inv := hardenedInventory()
	set := func(kind, prop, value string) {
		for i := range inv.Resources {
			if inv.Resources[i].Kind == kind {
				inv.Resources[i].Properties[prop] = value
			}
		}
	}
	set("aws_s3_bucket", "public_access_block", "all false")
	set("aws_s3_bucket", "acl", "public-read")
	set("aws_db_instance", "publicly_accessible", "true")
	set("aws_db_instance", "storage_encrypted", "false")
	set("aws_security_group", "open_to_world", "true")
	set("Ingress", "tls", "none")
	set("Deployment", "privileged", "true")
	set("Deployment", "run_as_user", "0")
	set("Deployment", "env.DATABASE_PASSWORD", "literal")
	return inv
}

func inputWith(inv *infra.Inventory, ff ...findings.Finding) Input {
	return Input{
		NoxVersion: "9.9.9",
		Report: report.JSONReport{
			Meta:           report.Meta{SchemaVersion: "1.0.0", GeneratedAt: "2026-10-24T17:18:36Z", ToolName: "nox", ToolVersion: "1.2.3"},
			Infrastructure: inv,
			Findings:       ff,
		},
	}
}

func weakFindings() []findings.Finding {
	return []findings.Finding{
		finding("IAC-504", "critical", "deploy/tf/main.tf", 6, "public access block disabled", findings.StatusNew, cwe284),
		finding("IAC-036", "critical", "deploy/tf/main.tf", 24, "RDS or database instance is publicly accessible", findings.StatusNew, cwe284),
		finding("IAC-004", "high", "deploy/tf/main.tf", 15, "security group open to the world", findings.StatusNew, cwe284),
		finding("IAC-149", "high", "deploy/k8s/ingress.yaml", 1, "Ingress without TLS", findings.StatusNew, cwe284),
		finding("IAC-131", "high", "deploy/k8s/deployment.yaml", 20, "privileged container", findings.StatusNew, cwe284),
	}
}

func idsOf(refs []ElementRef) map[string]bool {
	out := map[string]bool{}
	for _, r := range refs {
		out[r.ID] = true
	}
	return out
}

// The defect this fixes: a hardened resource has no finding, so the model had
// no element for it, and the same resource weakened in the next commit was
// reported as new.
func TestHardenedResourcesAreElementsAndWeakeningIsNotNew(t *testing.T) {
	a := Build(inputWith(hardenedInventory()))
	b := Build(inputWith(weakenedInventory(), weakFindings()...))

	for _, want := range []string{
		"deploy:bucket:aws_s3_bucket/invoices@deploy/tf/main.tf",
		"deploy:database:aws_db_instance/main@deploy/tf/main.tf",
		"deploy:ingress:Ingress/invoicely@deploy/k8s/ingress.yaml",
		"deploy:network_rule:aws_security_group/db@deploy/tf/main.tf",
		"deploy:workload:Deployment/invoicely@deploy/k8s/deployment.yaml",
	} {
		if !hasElement(a, want) {
			t.Errorf("the hardened state has no element %q", want)
		}
	}

	d := Compare(a, b)
	if added := idsOf(d.ElementsAdded); len(added) != 0 {
		t.Errorf("resources that exist in both states were reported new: %v", added)
	}
	if len(d.ElementsRemoved) != 0 {
		t.Errorf("nothing was removed: %v", d.ElementsRemoved)
	}
	var lines []string
	for _, c := range d.PropertiesChanged {
		if c.Direction != infra.Weaker {
			t.Errorf("%s: expected weaker", c.Line())
		}
		lines = append(lines, c.Line())
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{
		"aws_s3_bucket.invoices (deploy/tf/main.tf): public access block — was all true, now all false",
		"aws_s3_bucket.invoices (deploy/tf/main.tf): ACL — was private, now public-read",
		"aws_db_instance.main (deploy/tf/main.tf): publicly accessible — was false, now true",
		"aws_db_instance.main (deploy/tf/main.tf): storage encrypted — was true, now false",
		"aws_security_group.db (deploy/tf/main.tf): open to the internet — was false, now true",
		"Ingress invoicely (deploy/k8s/ingress.yaml): TLS — was all hosts, now none",
		"Deployment invoicely (deploy/k8s/deployment.yaml): privileged — was false, now true",
		"Deployment invoicely (deploy/k8s/deployment.yaml): runAsUser — was 10001, now 0",
		"Deployment invoicely (deploy/k8s/deployment.yaml): env DATABASE_PASSWORD — was secretKeyRef, now a literal value",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing property change %q in:\n%s", want, all)
		}
	}
	term := d.Terminal()
	if strings.Contains(term, "new data store") || strings.Contains(term, "new ingress") || strings.Contains(term, "new network rule") {
		t.Errorf("the terminal still calls an existing resource new:\n%s", term)
	}
	if !strings.Contains(term, "weakened: aws_s3_bucket.invoices") {
		t.Errorf("the terminal does not show the weakened property:\n%s", term)
	}
}

// The findings on the weakened state land on the existing element, so its cells
// change instead of a second element appearing.
func TestFindingsAttachToTheResourceTheyAreIn(t *testing.T) {
	b := Build(inputWith(weakenedInventory(), weakFindings()...))
	if c := cell(t, b, "deploy:bucket:aws_s3_bucket/invoices@deploy/tf/main.tf", ElevationOfPrivilege); !strings.Contains(rules(c), "IAC-504") {
		t.Errorf("IAC-504 evidence = %q", rules(c))
	}
	if c := cell(t, b, "deploy:database:aws_db_instance/main@deploy/tf/main.tf", ElevationOfPrivilege); strings.Contains(rules(c), "IAC-504") {
		t.Errorf("the bucket's finding leaked onto the database: %q", rules(c))
	}
	e := elementByID(t, b, "deploy:ingress:Ingress/invoicely@deploy/k8s/ingress.yaml")
	if len(e.Evidence) < 2 {
		t.Errorf("the ingress element must cite its finding as well as its declaration: %+v", e.Evidence)
	}
	hasFlow := false
	for _, f := range b.Flows {
		if f.To == e.ID && f.From == "actor:internet" {
			hasFlow = true
		}
	}
	if !hasFlow {
		t.Error("IAC-149 says the ingress is reachable from outside; the exposure flow is lost")
	}

	d := Compare(Build(inputWith(hardenedInventory())), b)
	changed := false
	for _, c := range d.CellsChanged {
		if c.Element == "deploy:bucket:aws_s3_bucket/invoices@deploy/tf/main.tf" {
			changed = true
		}
	}
	if !changed {
		t.Errorf("the bucket's cells did not change: %+v", d.CellsChanged)
	}
}

func TestAResourceAddedInANewFileIsNew(t *testing.T) {
	cur := hardenedInventory()
	cur.Resources = append(cur.Resources, infra.Resource{
		Kind: "aws_s3_bucket", Name: "exports", File: "deploy/tf/exports.tf", Class: infra.ClassBucket,
		Properties: map[string]string{"public_access_block": "all true"},
	})
	cur.Normalize()
	d := Compare(Build(inputWith(hardenedInventory())), Build(inputWith(cur)))
	added := idsOf(d.ElementsAdded)
	if len(added) != 1 || !added["deploy:bucket:aws_s3_bucket/exports@deploy/tf/exports.tf"] {
		t.Errorf("want exactly the new bucket, got %v", added)
	}
	if len(d.PropertiesChanged) != 0 {
		t.Errorf("a new resource is not a property change: %+v", d.PropertiesChanged)
	}
}

// Moving a resource within its file changes lines and nothing else.
func TestAPureMoveChangesNothing(t *testing.T) {
	moved := hardenedInventory()
	for i := range moved.Resources {
		moved.Resources[i].Line += 40
		moved.Resources[i].EndLine += 40
	}
	d := Compare(Build(inputWith(hardenedInventory())), Build(inputWith(moved)))
	if !d.Empty() {
		t.Errorf("a pure move produced %+v", d)
	}
}

func TestReverseDirectionIsStrengthened(t *testing.T) {
	d := Compare(Build(inputWith(weakenedInventory(), weakFindings()...)), Build(inputWith(hardenedInventory())))
	if len(d.PropertiesChanged) == 0 {
		t.Fatal("hardening went unreported")
	}
	for _, c := range d.PropertiesChanged {
		if c.Direction != infra.Stronger {
			t.Errorf("%s should be strengthened", c.Line())
		}
	}
	if !strings.Contains(d.Terminal(), "strengthened: aws_s3_bucket.invoices") {
		t.Errorf("terminal:\n%s", d.Terminal())
	}
	if len(d.ElementsAdded)+len(d.ElementsRemoved) != 0 {
		t.Errorf("the same resources are neither added nor removed: %+v %+v", d.ElementsAdded, d.ElementsRemoved)
	}
}

// A previous model written before the inventory existed describes its deployment
// resources by finding-derived IDs. Comparing them to inventory IDs would report
// every resource as both gone and new.
func TestAPreInventoryPreviousModelGetsACaveatNotFalseNews(t *testing.T) {
	prev := Build(inputWith(nil, weakFindings()...))
	cur := Build(inputWith(weakenedInventory(), weakFindings()...))
	if prev.Provenance.Coverage.Infrastructure || !cur.Provenance.Coverage.Infrastructure {
		t.Fatal("premise: coverage differs")
	}
	d := Compare(prev, cur)
	for _, e := range append(d.ElementsAdded, d.ElementsRemoved...) {
		if strings.HasPrefix(e.ID, "deploy:") {
			t.Errorf("deployment element %q reported across an inventory gap", e.ID)
		}
	}
	found := false
	for _, c := range d.Caveats {
		if strings.Contains(c, "deployment inventory") {
			found = true
		}
	}
	if !found {
		t.Errorf("want a caveat naming the gap, got %v", d.Caveats)
	}
	if len(d.PropertiesChanged) != 0 {
		t.Errorf("nothing can be compared: %+v", d.PropertiesChanged)
	}
}

// A file with two buckets: a finding belongs to the bucket it sits in, and a
// finding above all of them to the first.
func TestFindingsInAFileOfSeveralBucketsAttachByPosition(t *testing.T) {
	inv := &infra.Inventory{Resources: []infra.Resource{
		{Kind: "aws_s3_bucket", Name: "one", File: "m.tf", Class: infra.ClassBucket, Line: 1, EndLine: 5},
		{Kind: "aws_s3_bucket", Name: "two", File: "m.tf", Class: infra.ClassBucket, Line: 7, EndLine: 12},
	}}
	inv.Normalize()
	m := Build(inputWith(inv, finding("IAC-040", "high", "m.tf", 9, "public ACL", findings.StatusNew, cwe284)))
	if rules(cell(t, m, "deploy:bucket:aws_s3_bucket/two@m.tf", ElevationOfPrivilege)) != "IAC-040" {
		t.Error("the finding sits in bucket two")
	}
	if cell(t, m, "deploy:bucket:aws_s3_bucket/one@m.tf", ElevationOfPrivilege).Status != NotEvidenced {
		t.Error("bucket one has nothing against it")
	}
}

// An infrastructure finding in a file the inventory knows nothing about still
// gets its element, as before.
func TestFindingsWithoutAnInventoryResourceFallBackToTheRuleElement(t *testing.T) {
	m := Build(inputWith(hardenedInventory(), finding("IAC-040", "high", "other/bucket.tf", 3, "public ACL", findings.StatusNew, cwe284)))
	if !hasElement(m, "deploy:bucket@other/bucket.tf") {
		t.Error("the finding lost its element")
	}
}

func TestModelCarriesThePropertiesOfAHardenedResource(t *testing.T) {
	m := Build(inputWith(hardenedInventory()))
	e := elementByID(t, m, "deploy:bucket:aws_s3_bucket/invoices@deploy/tf/main.tf")
	if e.Properties["public_access_block"] != "all true" || e.Attributes["basis"] != "inventory" {
		t.Errorf("element = %+v", e)
	}
	if !strings.Contains(m.Markdown(false), "public access block all true") {
		t.Error("the written model does not show the properties")
	}
}
