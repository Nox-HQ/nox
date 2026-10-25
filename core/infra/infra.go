// Package infra describes the deployment resources a scan read from
// infrastructure-as-code, and says which of their security-relevant properties
// got weaker or stronger between two scans.
//
// It exists because findings only describe what is wrong. A bucket whose public
// access is blocked produces no finding, so a scan that records findings alone
// cannot say, a week later, that the bucket was hardened and no longer is: all
// it can show is a new finding, with nothing tying it to the assumption it
// broke. This package records the resources themselves, hardened or not, so a
// later comparison can name the assumption ("the public access block was all
// true, now false"). docs/vision.md section 15: when an infrastructure change
// invalidates a previously established security assumption, nox should surface
// that change.
//
// The inventory is context, not findings. Nothing here is reported as an issue,
// counted by a gate or exported to SARIF; it is written under its own key in
// findings.json and read by `nox model` and the change summary.
//
// The package is pure: no I/O, no clock, no network. The same two inventories
// always produce the same changes, in the same order.
package infra

import (
	"sort"
	"strconv"
	"strings"
)

// SchemaVersion identifies the set of properties an inventory records. A
// property the earlier inventory did not record is never compared, so adding a
// property here cannot make an old inventory look weaker.
const SchemaVersion = 1

// Classes group resources by the role they play in a system model.
const (
	ClassBucket      = "bucket"
	ClassDatabase    = "database"
	ClassIngress     = "ingress"
	ClassWorkload    = "workload"
	ClassImage       = "image"
	ClassNetworkRule = "network_rule"
)

// Resource is one deployment resource and the security-relevant properties nox
// could read from it.
type Resource struct {
	// Kind is the resource type as the document spells it: "aws_s3_bucket",
	// "AWS::RDS::DBInstance", "Deployment", "Dockerfile", "compose_service".
	Kind string `json:"kind"`
	// Name is the name the document gives it ("uploads", "web"). Two resources
	// with the same kind, namespace, name and file are told apart by a "#2"
	// suffix in document order.
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	File      string `json:"file"`
	Class     string `json:"class"`
	// Line and EndLine locate the resource. They are presentation and a way to
	// attach findings; identity never includes them.
	Line    int `json:"line,omitempty"`
	EndLine int `json:"end_line,omitempty"`
	// Properties maps a property key to the value nox read. A value nox cannot
	// evaluate (a variable, a template) is recorded as "dynamic" and never
	// compared.
	Properties map[string]string `json:"properties,omitempty"`
}

// ID is the stable identity of a resource: kind, namespace, name and file, never
// a line.
func (r Resource) ID() string {
	id := r.Kind + "/"
	if r.Namespace != "" {
		id += r.Namespace + "/"
	}
	return id + r.Name + "@" + r.File
}

// Display names the resource the way its author does: "aws_s3_bucket.uploads"
// for a Terraform resource, "Deployment web" for a Kubernetes object.
func (r Resource) Display() string {
	switch {
	case r.Kind == "Dockerfile":
		return "Dockerfile"
	case isTerraformKind(r.Kind):
		return r.Kind + "." + r.Name
	}
	if r.Namespace != "" {
		return r.Kind + " " + r.Namespace + "/" + r.Name
	}
	return r.Kind + " " + r.Name
}

func isTerraformKind(kind string) bool {
	return strings.Contains(kind, "_") && kind == strings.ToLower(kind) && !strings.ContainsAny(kind, ":/ ")
}

// Inventory is every resource a scan read, in a fixed order.
type Inventory struct {
	Version   int        `json:"version"`
	Resources []Resource `json:"resources"`
}

// Normalize sorts the resources, makes identities unique and stamps the schema
// version. It is what makes the same tree always produce the same bytes.
func (inv *Inventory) Normalize() {
	inv.Version = SchemaVersion
	sort.SliceStable(inv.Resources, func(i, j int) bool {
		a, b := inv.Resources[i], inv.Resources[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Line < b.Line
	})
	seen := map[string]int{}
	for i := range inv.Resources {
		r := &inv.Resources[i]
		seen[r.ID()]++
		if n := seen[r.ID()]; n > 1 {
			r.Name += "#" + strconv.Itoa(n)
		}
	}
}

// Empty reports whether no resource was read.
func (inv Inventory) Empty() bool { return len(inv.Resources) == 0 }

// Index returns the resources by identity.
func (inv Inventory) Index() map[string]Resource {
	out := make(map[string]Resource, len(inv.Resources))
	for _, r := range inv.Resources {
		out[r.ID()] = r
	}
	return out
}
