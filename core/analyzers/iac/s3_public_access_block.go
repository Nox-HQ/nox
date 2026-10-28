package iac

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// IAC-504 matches one line, and a Terraform S3 public access block has four
// independent switches. A resource with all four off therefore produced four
// findings with the same message, which counted one misconfiguration four times
// and told a person "in 4 places" about a block they edit once.
//
// The claim is about the resource, so the finding is too: one per resource (or
// per enclosing block, for a module call or a tfvars file), naming the switches
// that are off. The rule keeps its ID; only the granularity of the claim moves.

const ruleS3PublicAccessBlock = "IAC-504"

var (
	s3FlagRe = regexp.MustCompile(`(?i)^\s*(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\b`)

	tfResourceRe = regexp.MustCompile(`^\s*resource\s+"([^"]+)"\s+"([^"]+)"`)
	tfDataRe     = regexp.MustCompile(`^\s*data\s+"([^"]+)"\s+"([^"]+)"`)
	tfModuleRe   = regexp.MustCompile(`^\s*module\s+"([^"]+)"`)
)

// collapsePublicAccessBlock folds the IAC-504 findings of one block into one.
// Findings it folds away are recorded as refuted with the reason, so the stage
// accounting shows the candidates and not only the survivor.
func collapsePublicAccessBlock(in []findings.Finding, content []byte, drop refuteFunc) []findings.Finding {
	var idx []int
	for i := range in {
		if in[i].RuleID == ruleS3PublicAccessBlock {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return in
	}
	lines := strings.Split(string(content), "\n")
	blocks := tfBlockHeaders(lines)

	groups := map[int][]int{}
	var order []int
	for _, i := range idx {
		key := blocks[in[i].Location.StartLine]
		if _, seen := groups[key.start]; !seen {
			order = append(order, key.start)
		}
		groups[key.start] = append(groups[key.start], i)
	}

	folded := map[int]bool{}
	for _, start := range order {
		members := groups[start]
		sort.SliceStable(members, func(a, b int) bool {
			return in[members[a]].Location.StartLine < in[members[b]].Location.StartLine
		})
		first := members[0]
		addr := blocks[in[first].Location.StartLine].address
		merged := mergePublicAccessFlags(in, members, lines, addr)
		for _, m := range members[1:] {
			drop(in[m], "folded into the one IAC-504 finding for "+addr+
				": its switches are one misconfiguration of one resource")
			folded[m] = true
		}
		in[first] = merged
	}

	kept := in[:0]
	for i := range in {
		if !folded[i] {
			kept = append(kept, in[i])
		}
	}
	return kept
}

// mergePublicAccessFlags builds the single finding for a block from the first
// finding of its group, naming every switch that is off.
func mergePublicAccessFlags(in []findings.Finding, members []int, lines []string, addr string) findings.Finding {
	f := in[members[0]]
	last := in[members[len(members)-1]]
	var flags []string
	for _, m := range members {
		line := in[m].Location.StartLine
		if line < 1 || line > len(lines) {
			continue
		}
		if sub := s3FlagRe.FindStringSubmatch(lines[line-1]); sub != nil {
			flags = appendUnique(flags, strings.ToLower(sub[1]))
		}
	}
	verb := "is"
	if len(flags) > 1 {
		verb = "are"
	}
	f.Message = fmt.Sprintf("%s: %s %s set to false in %s", f.Message, joinAnd(flags), verb, addr)
	f.Location.EndLine, f.Location.EndColumn = last.Location.EndLine, last.Location.EndColumn
	f.Metadata = cloneMetadata(f.Metadata)
	f.Metadata["resource"] = addr
	f.Metadata["flags"] = strings.Join(flags, ",")
	// Identity follows the resource, not the switches: fixing one of four must
	// not turn the finding into a different one and orphan a waiver on it.
	f.Fingerprint = findings.ComputeFingerprint(f.RuleID, f.Location, addr)
	fp := f.Fingerprint
	if len(fp) > 12 {
		fp = fp[:12]
	}
	f.ID = f.RuleID + "-" + fp
	return f
}

func appendUnique(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func cloneMetadata(m map[string]string) map[string]string {
	out := make(map[string]string, len(m)+2)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// tfBlock is the top-level block a line sits in.
type tfBlock struct {
	// start is the 1-based line of the block header, 0 outside any block.
	start int
	// address is how Terraform names it: aws_s3_bucket_public_access_block.x,
	// module.x, data.t.n; or the header text for another block kind. Outside
	// any block it is "this file".
	address string
}

// tfBlockHeaders maps every line to the top-level block that contains it. A
// block is read by brace depth over the line with its string literals and
// comments removed, which is enough for the shapes Terraform is written in; a
// line outside every block (a tfvars assignment) maps to the file.
func tfBlockHeaders(lines []string) map[int]tfBlock {
	out := make(map[int]tfBlock, len(lines))
	depth := 0
	var cur tfBlock
	for i, raw := range lines {
		n := i + 1
		code := stripHCLNoise(raw)
		if depth == 0 && strings.Contains(code, "{") {
			cur = tfBlock{start: n, address: tfAddress(raw)}
		}
		if depth == 0 && cur.start != n {
			cur = tfBlock{address: "this file"}
		}
		out[n] = cur
		depth += strings.Count(code, "{") - strings.Count(code, "}")
		if depth < 0 {
			depth = 0
		}
	}
	return out
}

// stripHCLNoise removes quoted strings and trailing comments so braces inside
// them are not counted.
func stripHCLNoise(line string) string {
	var b strings.Builder
	inStr := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inStr:
			switch c {
			case '\\':
				i++
			case '"':
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '#', c == '/' && i+1 < len(line) && line[i+1] == '/':
			return b.String()
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func tfAddress(header string) string {
	switch {
	case tfResourceRe.MatchString(header):
		m := tfResourceRe.FindStringSubmatch(header)
		return m[1] + "." + m[2]
	case tfDataRe.MatchString(header):
		m := tfDataRe.FindStringSubmatch(header)
		return "data." + m[1] + "." + m[2]
	case tfModuleRe.MatchString(header):
		return "module." + tfModuleRe.FindStringSubmatch(header)[1]
	}
	h := strings.TrimSpace(header)
	if i := strings.Index(h, "{"); i >= 0 {
		h = strings.TrimSpace(h[:i])
	}
	if h == "" {
		return "this file"
	}
	return h
}
