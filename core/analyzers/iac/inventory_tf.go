package iac

import (
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/infra"
)

// tfFile is the Terraform a single file declares, kept until every file has
// been read: a bucket's public access block is routinely a separate resource,
// often in another file, and it is the reference between them that says which
// bucket it protects.
type tfFile struct {
	path   string
	blocks []*hclBlock
}

// tfRes is one `resource` block and the file it is in.
type tfRes struct {
	file string
	b    *hclBlock
}

// tfPublicAccessFlags are the four switches of a public access block.
var tfPublicAccessFlags = []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}

type tfIndex map[string][]tfRes

// referencing returns the resources of a type whose attr points at target
// ("aws_s3_bucket.uploads"), as a reference and not as a longer name.
func (ix tfIndex) referencing(typ, attr, target string) []tfRes {
	re := regexp.MustCompile(`(^|[^A-Za-z0-9_.-])` + regexp.QuoteMeta(target) + `([^A-Za-z0-9_-]|$)`)
	var out []tfRes
	for _, l := range ix[typ] {
		if re.MatchString(l.b.attrs[attr]) {
			out = append(out, l)
		}
	}
	return out
}

// tfResources derives the inventory resources from every Terraform file.
func tfResources(files []tfFile) []infra.Resource {
	ix := tfIndex{}
	var all []tfRes
	for _, f := range files {
		for _, b := range f.blocks {
			if b.typ == "resource" && len(b.labels) == 2 {
				l := tfRes{f.path, b}
				all = append(all, l)
				ix[b.labels[0]] = append(ix[b.labels[0]], l)
			}
		}
	}

	var out []infra.Resource
	attached := map[*hclBlock]bool{}
	for _, l := range all {
		typ, name := l.b.labels[0], l.b.labels[1]
		target := typ + "." + name
		r := infra.Resource{
			Kind: typ, Name: name, File: l.file, Line: l.b.line, EndLine: l.b.endLine,
			Properties: map[string]string{},
		}
		switch typ {
		case "aws_s3_bucket":
			r.Class = infra.ClassBucket
			r.Properties["public_access_block"] = tfAccessBlock(ix.referencing("aws_s3_bucket_public_access_block", "bucket", target))
			r.Properties["acl"] = tfBucketACL(l.b, ix.referencing("aws_s3_bucket_acl", "bucket", target))
			r.Properties["encryption"] = tfBucketEncryption(l.b, ix.referencing("aws_s3_bucket_server_side_encryption_configuration", "bucket", target))
		case "aws_db_instance":
			r.Class = infra.ClassDatabase
			r.Properties["publicly_accessible"] = tfBoolDefaultFalse(l.b, "publicly_accessible")
			r.Properties["storage_encrypted"] = tfBoolDefaultFalse(l.b, "storage_encrypted")
		case "aws_rds_cluster":
			r.Class = infra.ClassDatabase
			r.Properties["storage_encrypted"] = tfBoolDefaultFalse(l.b, "storage_encrypted")
		case "aws_rds_cluster_instance":
			r.Class = infra.ClassDatabase
			r.Properties["publicly_accessible"] = tfBoolDefaultFalse(l.b, "publicly_accessible")
		case "aws_security_group":
			r.Class = infra.ClassNetworkRule
			cidrs := tfSGCidrs(l.b)
			for _, rule := range ix.referencing("aws_security_group_rule", "security_group_id", target) {
				attached[rule.b] = true
				if t, ok := literalString(rule.b.attrs["type"]); ok && t == "ingress" {
					cidrs = append(cidrs, tfCidrAttrs(rule.b, "cidr_blocks", "ipv6_cidr_blocks")...)
				}
			}
			for _, rule := range ix.referencing("aws_vpc_security_group_ingress_rule", "security_group_id", target) {
				attached[rule.b] = true
				cidrs = append(cidrs, tfCidrAttrs(rule.b, "cidr_ipv4", "cidr_ipv6")...)
			}
			setCIDRProperties(&r, cidrs)
		default:
			continue
		}
		out = append(out, r)
	}
	// A standalone ingress rule that names no security group declared here is a
	// resource of its own.
	for _, typ := range []string{"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"} {
		for _, l := range ix[typ] {
			if attached[l.b] {
				continue
			}
			if typ == "aws_security_group_rule" {
				if t, ok := literalString(l.b.attrs["type"]); !ok || t != "ingress" {
					continue
				}
			}
			r := infra.Resource{
				Kind: typ, Name: l.b.labels[1], File: l.file, Line: l.b.line, EndLine: l.b.endLine,
				Class: infra.ClassNetworkRule, Properties: map[string]string{},
			}
			setCIDRProperties(&r, tfCidrAttrs(l.b, "cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6"))
			out = append(out, r)
		}
	}
	return out
}

// setCIDRProperties records whether a rule set admits the whole internet, and
// the literal CIDRs for context.
func setCIDRProperties(r *infra.Resource, cidrs []string) {
	dynamic := false
	var literal []string
	for _, c := range cidrs {
		if c == infra.Dynamic {
			dynamic = true
			continue
		}
		literal = append(literal, c)
	}
	sort.Strings(literal)
	world := "false"
	for _, c := range literal {
		if c == "0.0.0.0/0" || c == "::/0" {
			world = "true"
		}
	}
	if world == "false" && dynamic {
		world = infra.Dynamic
	}
	r.Properties["open_to_world"] = world
	if len(literal) > 0 {
		r.Properties["ingress_cidrs"] = strings.Join(literal, ", ")
	}
}

// tfCidrAttrs reads the CIDR attributes of a block; an expression becomes
// infra.Dynamic.
func tfCidrAttrs(b *hclBlock, attrs ...string) []string {
	var out []string
	for _, a := range attrs {
		expr, ok := b.attrs[a]
		if !ok {
			continue
		}
		if list, ok := literalStrings(expr); ok {
			out = append(out, list...)
		} else if v, ok := literalString(expr); ok {
			out = append(out, v)
		} else {
			out = append(out, infra.Dynamic)
		}
	}
	return out
}

func tfSGCidrs(b *hclBlock) []string {
	var out []string
	for _, ing := range b.childrenOf("ingress") {
		out = append(out, tfCidrAttrs(ing, "cidr_blocks", "ipv6_cidr_blocks")...)
	}
	if len(b.childrenOf("dynamic")) > 0 {
		out = append(out, infra.Dynamic)
	}
	return out
}

// tfBoolDefaultFalse reads a boolean attribute whose provider default is false.
func tfBoolDefaultFalse(b *hclBlock, attr string) string {
	expr, ok := b.attrs[attr]
	if !ok {
		return "false"
	}
	if v, ok := literalBool(expr); ok && v {
		return "true"
	} else if ok {
		return "false"
	}
	return infra.Dynamic
}

// tfAccessBlock summarises the public access blocks that protect a bucket. No
// block at all is "absent": the bucket relies on its policy or ACL alone.
func tfAccessBlock(blocks []tfRes) string {
	if len(blocks) == 0 {
		return "absent"
	}
	off := map[string]bool{}
	for _, flag := range tfPublicAccessFlags {
		// A flag is off unless some block turns it on; an unevaluated flag
		// cannot be said to be on or off.
		on := false
		for _, blk := range blocks {
			expr, set := blk.b.attrs[flag]
			if !set {
				continue
			}
			v, ok := literalBool(expr)
			if !ok {
				return infra.Dynamic
			}
			on = on || v
		}
		if !on {
			off[flag] = true
		}
	}
	return accessBlockValue(len(tfPublicAccessFlags), off)
}

// accessBlockValue words the state of a public access block from the flags
// that are off.
func accessBlockValue(total int, off map[string]bool) string {
	switch len(off) {
	case 0:
		return "all true"
	case total:
		return "all false"
	}
	names := make([]string, 0, len(off))
	for k := range off {
		names = append(names, k)
	}
	sort.Strings(names)
	return "partial (false: " + strings.Join(names, ", ") + ")"
}

// tfBucketACL reads the ACL from the bucket or from an aws_s3_bucket_acl that
// references it. Absent means private, which is the AWS default.
func tfBucketACL(bucket *hclBlock, acls []tfRes) string {
	expr, ok := bucket.attrs["acl"]
	for _, a := range acls {
		if e, set := a.b.attrs["acl"]; set {
			expr, ok = e, true
		}
	}
	if !ok {
		return "private"
	}
	if v, ok := literalString(expr); ok {
		return v
	}
	return infra.Dynamic
}

// tfBucketEncryption reads the default encryption of a bucket, from the bucket
// itself or from a separate configuration resource that references it.
func tfBucketEncryption(bucket *hclBlock, cfgs []tfRes) string {
	holders := []*hclBlock{bucket}
	for _, c := range cfgs {
		holders = append(holders, c.b)
	}
	best := "none"
	for _, h := range holders {
		for _, rule := range sseRules(h) {
			by := rule.child("apply_server_side_encryption_by_default")
			if by == nil {
				continue
			}
			algo, ok := literalString(by.attrs["sse_algorithm"])
			if !ok {
				return infra.Dynamic
			}
			if strings.HasPrefix(algo, "aws:kms") {
				algo = "aws:kms"
			}
			if algo == "aws:kms" || best == "none" {
				best = algo
			}
		}
	}
	return best
}

// sseRules finds the `rule` blocks of a bucket or of its configuration
// resource; the inline form nests them one level deeper.
func sseRules(h *hclBlock) []*hclBlock {
	if inline := h.child("server_side_encryption_configuration"); inline != nil {
		return inline.childrenOf("rule")
	}
	return h.childrenOf("rule")
}
