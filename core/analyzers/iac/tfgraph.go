// tfgraph.go implements graph-based cross-resource analysis for Terraform
// plans. It builds a resource dependency graph from HCL configuration
// references and detects misconfigurations that span multiple resources.
//
// Cross-resource rules:
//   - IAC-366: Public subnet + unrestricted security group in same VPC
//   - IAC-367: Internet-facing load balancer with HTTP listener (no TLS)
//   - IAC-368: Public S3 bucket without server-side encryption config
//   - IAC-369: Unrestricted security group attached to database instance
package iac

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/graph"
)

// Cross-resource rule IDs.
const (
	rulePublicSubnetOpenSG   = "IAC-366"
	ruleInternetLBHTTP       = "IAC-367"
	rulePublicS3NoEncryption = "IAC-368"
	ruleOpenSGOnDatabase     = "IAC-369"
)

// resourceEntry holds merged resource data from plan values and configuration references.
type resourceEntry struct {
	Address string
	Type    string
	Name    string
	Values  map[string]interface{}
	Refs    map[string][]string // field → referenced resource addresses
}

// resourceIndex enables efficient cross-resource lookup by address and type.
type resourceIndex struct {
	entries   []*resourceEntry
	byAddress map[string]*resourceEntry
	byType    map[string][]*resourceEntry
}

func newResourceIndex(plan *tfPlan) *resourceIndex {
	idx := &resourceIndex{
		byAddress: make(map[string]*resourceEntry),
		byType:    make(map[string][]*resourceEntry),
	}

	// Build entries from resource changes (preferred — contains "after" state).
	seen := make(map[string]bool)
	for _, rc := range plan.ResourceChanges {
		if rc.Change.After == nil {
			continue
		}
		idx.addEntry(&resourceEntry{
			Address: rc.Address,
			Type:    rc.Type,
			Values:  rc.Change.After,
			Refs:    make(map[string][]string),
		})
		seen[rc.Address] = true
	}

	// Fill in from planned values for resources without changes.
	for _, res := range plan.PlannedValues.RootModule.Resources {
		if seen[res.Address] || res.Values == nil {
			continue
		}
		idx.addEntry(&resourceEntry{
			Address: res.Address,
			Type:    res.Type,
			Name:    res.Name,
			Values:  res.Values,
			Refs:    make(map[string][]string),
		})
	}

	// Merge HCL configuration expression references.
	for _, cr := range plan.Configuration.RootModule.Resources {
		e, ok := idx.byAddress[cr.Address]
		if !ok {
			continue
		}
		if e.Name == "" {
			e.Name = cr.Name
		}
		for field, expr := range cr.Expressions {
			if len(expr.References) > 0 {
				e.Refs[field] = expr.References
			}
		}
	}

	return idx
}

func (idx *resourceIndex) addEntry(e *resourceEntry) {
	idx.entries = append(idx.entries, e)
	idx.byAddress[e.Address] = e
	idx.byType[e.Type] = append(idx.byType[e.Type], e)
}

// BuildResourceGraph parses a Terraform plan JSON and returns a resource
// dependency graph. Nodes represent resources; edges are inferred from HCL
// configuration references. The graph is useful for visualization and for
// downstream tools that need relationship context.
func BuildResourceGraph(planJSON []byte, path string) (*graph.Graph, error) {
	var plan tfPlan
	if err := json.Unmarshal(planJSON, &plan); err != nil {
		return nil, fmt.Errorf("parsing terraform plan JSON: %w", err)
	}
	idx := newResourceIndex(&plan)
	return buildResourceGraph(idx, path), nil
}

func buildResourceGraph(idx *resourceIndex, path string) *graph.Graph {
	g := &graph.Graph{
		Name:        "terraform-plan",
		Description: "Resource dependency graph from Terraform plan",
	}

	for _, e := range idx.entries {
		props := map[string]string{"type": e.Type}
		if e.Name != "" {
			props["name"] = e.Name
		}
		g.Nodes = append(g.Nodes, graph.Node{
			ID:         e.Address,
			Kind:       graph.NodeKindResource,
			Label:      e.Address,
			FilePath:   path,
			Properties: props,
		})
	}

	nodeIDs := g.NodeIDs()
	for _, e := range idx.entries {
		for field, refs := range e.Refs {
			for _, ref := range refs {
				target := normalizeRef(ref)
				if target != e.Address && nodeIDs[target] {
					g.Edges = append(g.Edges, graph.Edge{
						Source: e.Address,
						Target: target,
						Kind:   graph.EdgeKindDependsOn,
						Label:  field,
					})
				}
			}
		}
	}

	return g
}

// checkCrossResourcePatterns runs all graph-based cross-resource security checks.
func checkCrossResourcePatterns(idx *resourceIndex, fs *findings.FindingSet, path string) {
	openSGs := findOpenSecurityGroups(idx)
	checkPublicSubnetOpenSG(idx, openSGs, fs, path)
	checkInternetLBWithHTTP(idx, fs, path)
	checkPublicS3NoEncryption(idx, fs, path)
	checkOpenSGOnDatabase(idx, openSGs, fs, path)
}

// findOpenSecurityGroups returns security groups that allow unrestricted ingress.
func findOpenSecurityGroups(idx *resourceIndex) map[string]*resourceEntry {
	open := make(map[string]*resourceEntry)

	// Inline ingress blocks on aws_security_group resources.
	for _, sg := range idx.byType["aws_security_group"] {
		if hasOpenIngress(sg.Values) {
			open[sg.Address] = sg
		}
	}

	// Separate aws_security_group_rule resources with type=ingress.
	for _, rule := range idx.byType["aws_security_group_rule"] {
		ruleType, _ := getString(rule.Values, "type")
		if ruleType != "ingress" {
			continue
		}
		if !hasOpenCIDR(rule.Values) {
			continue
		}
		sgAddr := securityGroupRef(rule)
		if sgAddr != "" {
			if sg, ok := idx.byAddress[sgAddr]; ok {
				open[sgAddr] = sg
			}
		}
	}

	return open
}

// checkPublicSubnetOpenSG detects IAC-366: public subnet coexists with an
// unrestricted security group in the same VPC.
func checkPublicSubnetOpenSG(idx *resourceIndex, openSGs map[string]*resourceEntry, fs *findings.FindingSet, path string) {
	for _, subnet := range idx.byType["aws_subnet"] {
		val, ok := getBool(subnet.Values, "map_public_ip_on_launch")
		if !ok || !val {
			continue
		}
		subnetVPC := vpcRef(subnet)
		if subnetVPC == "" {
			continue
		}
		for addr, sg := range openSGs {
			if vpcRef(sg) == subnetVPC {
				fs.Add(findings.Finding{
					RuleID:     rulePublicSubnetOpenSG,
					Severity:   findings.SeverityCritical,
					Confidence: findings.ConfidenceMedium,
					Location:   findings.Location{FilePath: path, StartLine: 1},
					Message:    fmt.Sprintf("Public subnet %s and unrestricted security group %s share the same VPC — network boundary is ineffective", subnet.Address, addr),
					Metadata:   map[string]string{"subnet": subnet.Address, "security_group": addr, "source": "terraform-plan-graph"},
				})
			}
		}
	}
}

// checkInternetLBWithHTTP detects IAC-367: internet-facing load balancer
// with an HTTP listener (no TLS termination).
func checkInternetLBWithHTTP(idx *resourceIndex, fs *findings.FindingSet, path string) {
	publicLBs := make(map[string]*resourceEntry)
	for _, lbType := range []string{"aws_lb", "aws_alb"} {
		for _, lb := range idx.byType[lbType] {
			if val, ok := getBool(lb.Values, "internal"); ok && !val {
				publicLBs[lb.Address] = lb
			}
		}
	}
	if len(publicLBs) == 0 {
		return
	}

	for _, listenerType := range []string{"aws_lb_listener", "aws_alb_listener"} {
		for _, listener := range idx.byType[listenerType] {
			proto, _ := getString(listener.Values, "protocol")
			if !strings.EqualFold(proto, "HTTP") {
				continue
			}
			for _, ref := range listener.Refs["load_balancer_arn"] {
				target := normalizeRef(ref)
				if lb, ok := publicLBs[target]; ok {
					fs.Add(findings.Finding{
						RuleID:     ruleInternetLBHTTP,
						Severity:   findings.SeverityHigh,
						Confidence: findings.ConfidenceHigh,
						Location:   findings.Location{FilePath: path, StartLine: 1},
						Message:    fmt.Sprintf("Internet-facing load balancer %s has HTTP listener %s without TLS termination", lb.Address, listener.Address),
						Metadata:   map[string]string{"load_balancer": lb.Address, "listener": listener.Address, "source": "terraform-plan-graph"},
					})
				}
			}
		}
	}
}

// checkPublicS3NoEncryption detects IAC-368: public S3 bucket without
// a server-side encryption configuration resource.
func checkPublicS3NoEncryption(idx *resourceIndex, fs *findings.FindingSet, path string) {
	publicBuckets := make(map[string]*resourceEntry)
	for _, e := range idx.byType["aws_s3_bucket"] {
		acl, ok := getString(e.Values, "acl")
		if ok && (acl == "public-read" || acl == "public-read-write") {
			publicBuckets[e.Address] = e
		}
	}
	if len(publicBuckets) == 0 {
		return
	}

	// Determine which buckets have encryption configuration.
	encrypted := make(map[string]bool)
	for _, e := range idx.byType["aws_s3_bucket_server_side_encryption_configuration"] {
		for _, ref := range e.Refs["bucket"] {
			encrypted[normalizeRef(ref)] = true
		}
	}

	for addr, bucket := range publicBuckets {
		if !encrypted[addr] {
			fs.Add(findings.Finding{
				RuleID:     rulePublicS3NoEncryption,
				Severity:   findings.SeverityCritical,
				Confidence: findings.ConfidenceHigh,
				Location:   findings.Location{FilePath: path, StartLine: 1},
				Message:    fmt.Sprintf("Public S3 bucket %s has no server-side encryption configuration", bucket.Address),
				Metadata:   map[string]string{"bucket": bucket.Address, "source": "terraform-plan-graph"},
			})
		}
	}
}

// checkOpenSGOnDatabase detects IAC-369: unrestricted security group
// attached to a database instance.
func checkOpenSGOnDatabase(idx *resourceIndex, openSGs map[string]*resourceEntry, fs *findings.FindingSet, path string) {
	if len(openSGs) == 0 {
		return
	}
	for _, dbType := range []string{"aws_db_instance", "aws_rds_cluster"} {
		for _, db := range idx.byType[dbType] {
			for _, ref := range db.Refs["vpc_security_group_ids"] {
				target := normalizeRef(ref)
				if _, ok := openSGs[target]; ok {
					fs.Add(findings.Finding{
						RuleID:     ruleOpenSGOnDatabase,
						Severity:   findings.SeverityCritical,
						Confidence: findings.ConfidenceHigh,
						Location:   findings.Location{FilePath: path, StartLine: 1},
						Message:    fmt.Sprintf("Database %s uses unrestricted security group %s — database exposed to 0.0.0.0/0", db.Address, target),
						Metadata:   map[string]string{"database": db.Address, "security_group": target, "source": "terraform-plan-graph"},
					})
				}
			}
		}
	}
}

// --- Helpers ---

// normalizeRef strips Terraform attribute suffixes from resource references.
// For example, "aws_vpc.main.id" becomes "aws_vpc.main".
func normalizeRef(ref string) string {
	parts := strings.Split(ref, ".")
	if len(parts) >= 3 {
		candidate := parts[len(parts)-1]
		if knownAttributes[candidate] {
			return strings.Join(parts[:len(parts)-1], ".")
		}
	}
	return ref
}

var knownAttributes = map[string]bool{
	"id": true, "arn": true, "name": true, "self_link": true,
	"unique_id": true, "dns_name": true, "bucket": true,
	"domain_name": true, "endpoint": true,
}

// vpcRef returns the VPC reference for a resource, checking configuration
// references first, then falling back to the planned value.
func vpcRef(e *resourceEntry) string {
	if refs, ok := e.Refs["vpc_id"]; ok && len(refs) > 0 {
		return normalizeRef(refs[0])
	}
	if v, ok := getString(e.Values, "vpc_id"); ok && v != "" {
		return v
	}
	return ""
}

// securityGroupRef returns the parent security group address for a
// separate aws_security_group_rule resource.
func securityGroupRef(rule *resourceEntry) string {
	if refs, ok := rule.Refs["security_group_id"]; ok && len(refs) > 0 {
		return normalizeRef(refs[0])
	}
	return ""
}

// hasOpenIngress checks if a security group's inline ingress rules allow
// unrestricted access (0.0.0.0/0 or ::/0).
func hasOpenIngress(values map[string]interface{}) bool {
	ingress, ok := values["ingress"]
	if !ok {
		return false
	}
	ingressList, ok := ingress.([]interface{})
	if !ok {
		return false
	}
	for _, item := range ingressList {
		ruleMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if hasOpenCIDR(ruleMap) {
			return true
		}
	}
	return false
}

// hasOpenCIDR checks if a values map contains cidr_blocks with 0.0.0.0/0 or ::/0.
func hasOpenCIDR(values map[string]interface{}) bool {
	for _, field := range []string{"cidr_blocks", "ipv6_cidr_blocks"} {
		cidrs, ok := getStringSlice(values, field)
		if !ok {
			continue
		}
		for _, cidr := range cidrs {
			if cidr == "0.0.0.0/0" || cidr == "::/0" {
				return true
			}
		}
	}
	return false
}
