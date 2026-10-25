package iac

import (
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nox-hq/nox/core/infra"
	"github.com/nox-hq/nox/core/rules/structural"
)

// fileInfra is what one file contributes to the inventory. Terraform is kept as
// parsed blocks, not resources, because resources there reference each other
// across files; everything else is complete on its own.
type fileInfra struct {
	path      string
	resources []infra.Resource
	tf        []*hclBlock
}

// extractFileInfra reads the deployment resources one file declares. parsed is
// the file's already-parsed YAML resources (the index every scan builds), so
// Kubernetes and CloudFormation are read once.
func extractFileInfra(path string, content []byte, parsed []structural.Resource) fileInfra {
	out := fileInfra{path: path}
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.HasSuffix(base, ".tf"):
		out.tf = parseHCL(content)
	case isDockerfilePath(base):
		out.resources = append(out.resources, dockerfileResources(path, content)...)
	case isComposeFile(path):
		out.resources = append(out.resources, composeResources(path, content)...)
	}
	for _, r := range parsed {
		switch r.Family {
		case structural.FamilyKubernetes:
			out.resources = append(out.resources, k8sResources(path, r)...)
		case structural.FamilyCloudFormation:
			out.resources = append(out.resources, cfnResources(path, r)...)
		}
	}
	return out
}

// InventoryFile is one file offered to BuildInventory.
type InventoryFile struct {
	Path    string
	Content []byte
}

// BuildInventory reads the deployment resources declared in files. A scan builds
// the same inventory as a side effect of reading them (Analyzer.Inventory), so
// the two cannot disagree about what a tree contains.
func BuildInventory(files []InventoryFile) infra.Inventory {
	per := make([]fileInfra, len(files))
	for i, f := range files {
		per[i] = extractFileInfra(f.Path, f.Content, structural.ParseResources(f.Content))
	}
	return assembleInventory(per)
}

// assembleInventory joins the per-file contributions into one inventory.
func assembleInventory(per []fileInfra) infra.Inventory {
	var inv infra.Inventory
	var tf []tfFile
	for _, p := range per {
		inv.Resources = append(inv.Resources, p.resources...)
		if p.tf != nil {
			tf = append(tf, tfFile{path: p.path, blocks: p.tf})
		}
	}
	inv.Resources = append(inv.Resources, tfResources(tf)...)
	inv.Normalize()
	return inv
}

func isDockerfilePath(lowerBase string) bool {
	return lowerBase == "dockerfile" || strings.HasPrefix(lowerBase, "dockerfile.") ||
		strings.HasSuffix(lowerBase, ".dockerfile") || lowerBase == "containerfile"
}

// ---- Kubernetes ---------------------------------------------------------------

var workloadKinds = map[string]bool{
	"Deployment": true, "StatefulSet": true, "DaemonSet": true, "ReplicaSet": true,
	"Job": true, "CronJob": true, "Pod": true,
}

func k8sResources(path string, r structural.Resource) []infra.Resource {
	// The resource starts at its first key, so a finding on the apiVersion line
	// belongs to this document and not to the one above it.
	start := r.Line
	if r.Props != nil && r.Props.Line > 0 && r.Props.Line < start {
		start = r.Props.Line
	}
	base := infra.Resource{
		Kind: r.Type, Name: r.Name, Namespace: scalar(mapChild(mapChild(r.Props, "metadata"), "namespace")),
		File: path, Line: start, EndLine: maxLine(r.Props), Properties: map[string]string{},
	}
	switch {
	case workloadKinds[r.Type]:
		pod := podSpec(r)
		if pod == nil {
			return nil
		}
		base.Class = infra.ClassWorkload
		workloadProperties(&base, pod)
		return []infra.Resource{base}
	case r.Type == "Ingress":
		base.Class = infra.ClassIngress
		ingressProperties(&base, r.Props)
		return []infra.Resource{base}
	}
	return nil
}

// podSpec returns the pod spec of a workload.
func podSpec(r structural.Resource) *yaml.Node {
	spec := mapChild(r.Props, "spec")
	switch r.Type {
	case "Pod":
		return spec
	case "CronJob":
		return mapChild(mapChild(mapChild(mapChild(spec, "jobTemplate"), "spec"), "template"), "spec")
	}
	return mapChild(mapChild(spec, "template"), "spec")
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// maxLine is the last line any node under n sits on.
func maxLine(n *yaml.Node) int {
	if n == nil {
		return 0
	}
	last := n.Line
	for _, c := range n.Content {
		if l := maxLine(c); l > last {
			last = l
		}
	}
	return last
}

// yamlBool reads a boolean node: set is whether it is present, ok whether it is
// a plain true or false.
func yamlBool(n *yaml.Node) (value, set, ok bool) {
	if n == nil {
		return false, false, true
	}
	switch strings.ToLower(scalar(n)) {
	case "true":
		return true, true, true
	case "false":
		return false, true, true
	}
	return false, true, false
}

func workloadProperties(r *infra.Resource, pod *yaml.Node) {
	var containers []*yaml.Node
	for _, key := range []string{"containers", "initContainers"} {
		if seq := mapChild(pod, key); seq != nil && seq.Kind == yaml.SequenceNode {
			containers = append(containers, seq.Content...)
		}
	}
	podSC := mapChild(pod, "securityContext")
	sc := func(c *yaml.Node) *yaml.Node { return mapChild(c, "securityContext") }

	r.Properties["privileged"] = anyBool(containers, func(c *yaml.Node) *yaml.Node { return mapChild(sc(c), "privileged") })
	for _, h := range [][2]string{{"host_network", "hostNetwork"}, {"host_pid", "hostPID"}, {"host_ipc", "hostIPC"}} {
		r.Properties[h[0]] = boolProp(mapChild(pod, h[1]), "false")
	}
	r.Properties["run_as_non_root"] = tristate(containers, func(c *yaml.Node) *yaml.Node {
		if n := mapChild(sc(c), "runAsNonRoot"); n != nil {
			return n
		}
		return mapChild(podSC, "runAsNonRoot")
	})
	r.Properties["run_as_user"] = runAsUser(containers, podSC, sc)
	r.Properties["allow_privilege_escalation"] = allExplicitFalse(containers, func(c *yaml.Node) *yaml.Node { return mapChild(sc(c), "allowPrivilegeEscalation") })
	r.Properties["read_only_root_fs"] = allTrue(containers, func(c *yaml.Node) *yaml.Node { return mapChild(sc(c), "readOnlyRootFilesystem") })
	r.Properties["capabilities_added"] = capabilitiesAdded(containers, sc)
	r.Properties["capabilities_drop_all"] = dropsAll(containers, sc)
	r.Properties["seccomp"] = seccompOf(containers, podSC, sc)
	r.Properties["automount_sa_token"] = automount(pod)
	if pin := imagePin(containers); pin != "" {
		r.Properties["image_pin"] = pin
	}
	envProperties(r, containers)
}

// boolProp renders an optional boolean; an expression is dynamic.
func boolProp(n *yaml.Node, def string) string {
	v, set, ok := yamlBool(n)
	switch {
	case !set:
		return def
	case !ok:
		return infra.Dynamic
	case v:
		return "true"
	}
	return "false"
}

// anyBool is "true" when any container sets the flag.
func anyBool(cs []*yaml.Node, get func(*yaml.Node) *yaml.Node) string {
	result := "false"
	for _, c := range cs {
		v, set, ok := yamlBool(get(c))
		switch {
		case !set:
		case !ok:
			return infra.Dynamic
		case v:
			result = "true"
		}
	}
	return result
}

// allTrue is "true" when every container sets the flag to true. No containers
// is "false": nothing was established.
func allTrue(cs []*yaml.Node, get func(*yaml.Node) *yaml.Node) string {
	if len(cs) == 0 {
		return "false"
	}
	for _, c := range cs {
		v, set, ok := yamlBool(get(c))
		switch {
		case set && !ok:
			return infra.Dynamic
		case !set || !v:
			return "false"
		}
	}
	return "true"
}

// allExplicitFalse is "false" when every container sets the flag to false, and
// "true" otherwise: Kubernetes allows privilege escalation unless told not to.
func allExplicitFalse(cs []*yaml.Node, get func(*yaml.Node) *yaml.Node) string {
	if len(cs) == 0 {
		return "true"
	}
	for _, c := range cs {
		v, set, ok := yamlBool(get(c))
		switch {
		case set && !ok:
			return infra.Dynamic
		case !set || v:
			return "true"
		}
	}
	return "false"
}

// tristate is "true" when every container resolves the flag to true, "false"
// when any resolves it to false, and "unset" otherwise.
func tristate(cs []*yaml.Node, get func(*yaml.Node) *yaml.Node) string {
	if len(cs) == 0 {
		return "unset"
	}
	anyUnset := false
	for _, c := range cs {
		v, set, ok := yamlBool(get(c))
		switch {
		case !set:
			anyUnset = true
		case !ok:
			return infra.Dynamic
		case !v:
			return "false"
		}
	}
	if anyUnset {
		return "unset"
	}
	return "true"
}

func runAsUser(cs []*yaml.Node, podSC *yaml.Node, sc func(*yaml.Node) *yaml.Node) string {
	first := ""
	all := len(cs) > 0
	for _, c := range cs {
		n := mapChild(sc(c), "runAsUser")
		if n == nil {
			n = mapChild(podSC, "runAsUser")
		}
		v := scalar(n)
		switch {
		case n == nil:
			all = false
		case v == "0":
			return "0"
		case strings.ContainsAny(v, "{$"):
			return infra.Dynamic
		case first == "":
			first = v
		}
	}
	if !all {
		return "unset"
	}
	return first
}

func capabilitiesAdded(cs []*yaml.Node, sc func(*yaml.Node) *yaml.Node) string {
	var items []*yaml.Node
	for _, c := range cs {
		items = append(items, seqItems(mapChild(mapChild(sc(c), "capabilities"), "add"))...)
	}
	return capabilitySummary(items)
}

// capabilitySummary words a set of added capabilities: "none", or the sorted
// names without the optional CAP_ prefix.
func capabilitySummary(items []*yaml.Node) string {
	set := map[string]bool{}
	for _, n := range items {
		set[strings.TrimPrefix(strings.ToUpper(scalar(n)), "CAP_")] = true
	}
	if len(set) == 0 {
		return "none"
	}
	names := make([]string, 0, len(set))
	for k := range set {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func dropsAll(cs []*yaml.Node, sc func(*yaml.Node) *yaml.Node) string {
	if len(cs) == 0 {
		return "false"
	}
	for _, c := range cs {
		found := false
		for _, n := range seqItems(mapChild(mapChild(sc(c), "capabilities"), "drop")) {
			if strings.EqualFold(scalar(n), "ALL") {
				found = true
			}
		}
		if !found {
			return "false"
		}
	}
	return "true"
}

func seqItems(n *yaml.Node) []*yaml.Node {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

func seccompOf(cs []*yaml.Node, podSC *yaml.Node, sc func(*yaml.Node) *yaml.Node) string {
	result := ""
	for _, c := range cs {
		t := scalar(mapChild(mapChild(sc(c), "seccompProfile"), "type"))
		if t == "" {
			t = scalar(mapChild(mapChild(podSC, "seccompProfile"), "type"))
		}
		switch {
		case t == "":
			return "unset"
		case t == "Unconfined":
			return "Unconfined"
		case result == "":
			result = t
		}
	}
	if result == "" {
		return "unset"
	}
	return result
}

func automount(pod *yaml.Node) string {
	return boolProp(mapChild(pod, "automountServiceAccountToken"), "true")
}

// imagePin is the weakest pin among the containers' images, or "" when none can
// be established (a template).
func imagePin(containers []*yaml.Node) string {
	weakest := ""
	rank := map[string]int{"unpinned": 0, "tag": 1, "digest": 2}
	for _, c := range containers {
		ref := scalar(mapChild(c, "image"))
		if ref == "" || strings.Contains(ref, "{{") {
			continue
		}
		pin := pinOf(ref)
		if pin == infra.Dynamic {
			return infra.Dynamic
		}
		if weakest == "" || rank[pin] < rank[weakest] {
			weakest = pin
		}
	}
	return weakest
}

// pinOf classifies an image reference as digest, tag or unpinned, reusing the
// rule that decides IAC-122 and the Compose image check so the two cannot
// disagree about what "pinned" means.
func pinOf(ref string) string {
	if strings.Contains(ref, "$") {
		resolved, complete := resolveComposeDefaults(ref)
		if !complete {
			return infra.Dynamic
		}
		ref = resolved
	}
	if _, digest, ok := strings.Cut(ref, "@"); ok && digest != "" {
		return "digest"
	}
	if _, unpinned := unpinnedImageReason(ref); unpinned {
		return "unpinned"
	}
	return "tag"
}

// envProperties records where each credential-named environment variable gets
// its value. A variable that is not named like a credential is not recorded:
// the inventory is for security assumptions, not for configuration.
func envProperties(r *infra.Resource, containers []*yaml.Node) {
	for _, c := range containers {
		for _, e := range seqItems(mapChild(c, "env")) {
			name := scalar(mapChild(e, "name"))
			if name == "" || !isCredentialName(name) {
				continue
			}
			source := ""
			switch {
			case mapChild(e, "valueFrom") != nil:
				from := mapChild(e, "valueFrom")
				switch {
				case mapChild(from, "secretKeyRef") != nil:
					source = "secretKeyRef"
				case mapChild(from, "configMapKeyRef") != nil:
					source = "configMapKeyRef"
				default:
					source = "valueFrom"
				}
			case mapChild(e, "value") != nil:
				source = literalSource(scalar(mapChild(e, "value")))
			}
			setEnv(r, name, source)
		}
	}
}

// literalSource classifies an inline value: a concrete value, a reference to
// something outside the file, or neither.
func literalSource(v string) string {
	switch {
	case isLiteralSecretValue(v):
		return "literal"
	case strings.Contains(v, "$"):
		return "variable"
	}
	return ""
}

// setEnv records a source, keeping the weakest when a name is set twice.
func setEnv(r *infra.Resource, name, source string) {
	if source == "" {
		return
	}
	key := "env." + name
	if old, ok := r.Properties[key]; ok {
		a, aok := infra.Rank(key, old)
		b, bok := infra.Rank(key, source)
		if aok && bok && a <= b {
			return
		}
	}
	r.Properties[key] = source
}

func ingressProperties(r *infra.Resource, ing *yaml.Node) {
	spec := mapChild(ing, "spec")
	r.Properties["tls"] = ingressTLS(spec)
	r.Properties["ssl_redirect"] = sslRedirect(mapChild(mapChild(ing, "metadata"), "annotations"))
}

func ingressTLS(spec *yaml.Node) string {
	tls := seqItems(mapChild(spec, "tls"))
	if len(tls) == 0 {
		return "none"
	}
	var covered []string
	for _, e := range tls {
		hosts := seqItems(mapChild(e, "hosts"))
		if len(hosts) == 0 {
			return "all hosts" // the default entry covers every host
		}
		for _, h := range hosts {
			covered = append(covered, strings.ToLower(h.Value))
		}
	}
	for _, rule := range seqItems(mapChild(spec, "rules")) {
		h := scalar(mapChild(rule, "host"))
		if h == "" || strings.ContainsAny(h, "{$") {
			continue
		}
		if !hostCovered(strings.ToLower(h), covered) {
			return "partial"
		}
	}
	return "all hosts"
}

func sslRedirect(annotations *yaml.Node) string {
	if annotations == nil || annotations.Kind != yaml.MappingNode {
		return "unset"
	}
	result := "unset"
	for i := 0; i+1 < len(annotations.Content); i += 2 {
		if !strings.HasSuffix(strings.ToLower(annotations.Content[i].Value), "ssl-redirect") {
			continue
		}
		switch strings.ToLower(annotations.Content[i+1].Value) {
		case "false":
			return "false"
		case "true":
			result = "true"
		}
	}
	return result
}

// ---- CloudFormation -------------------------------------------------------------

func cfnResources(path string, r structural.Resource) []infra.Resource {
	props := mapChild(r.Props, "Properties")
	base := infra.Resource{
		Kind: r.Type, Name: r.Name, File: path, Line: r.Line, EndLine: maxLine(r.Props),
		Properties: map[string]string{},
	}
	switch r.Type {
	case "AWS::S3::Bucket":
		base.Class = infra.ClassBucket
		base.Properties["public_access_block"] = cfnAccessBlock(mapChild(props, "PublicAccessBlockConfiguration"))
		base.Properties["acl"] = cfnString(mapChild(props, "AccessControl"), "private")
		base.Properties["encryption"] = cfnEncryption(props)
	case "AWS::RDS::DBInstance":
		base.Class = infra.ClassDatabase
		base.Properties["publicly_accessible"] = boolProp(mapChild(props, "PubliclyAccessible"), "false")
		base.Properties["storage_encrypted"] = boolProp(mapChild(props, "StorageEncrypted"), "false")
	case "AWS::RDS::DBCluster":
		base.Class = infra.ClassDatabase
		base.Properties["storage_encrypted"] = boolProp(mapChild(props, "StorageEncrypted"), "false")
	case "AWS::EC2::SecurityGroup":
		base.Class = infra.ClassNetworkRule
		var cidrs []string
		for _, rule := range seqItems(mapChild(props, "SecurityGroupIngress")) {
			for _, key := range []string{"CidrIp", "CidrIpv6"} {
				if n := mapChild(rule, key); n != nil {
					cidrs = append(cidrs, cfnString(n, infra.Dynamic))
				}
			}
		}
		setCIDRProperties(&base, cidrs)
	default:
		return nil
	}
	return []infra.Resource{base}
}

// cfnString reads a scalar that is a plain string; an intrinsic function
// (!Ref, Fn::Sub) is dynamic.
func cfnString(n *yaml.Node, def string) string {
	if n == nil {
		return def
	}
	if n.Kind != yaml.ScalarNode || strings.HasPrefix(n.Tag, "!") && n.Tag != "!!str" || strings.Contains(n.Value, "${") {
		return infra.Dynamic
	}
	return n.Value
}

func cfnAccessBlock(cfg *yaml.Node) string {
	if cfg == nil {
		return "absent"
	}
	flags := map[string]string{
		"BlockPublicAcls": "block_public_acls", "BlockPublicPolicy": "block_public_policy",
		"IgnorePublicAcls": "ignore_public_acls", "RestrictPublicBuckets": "restrict_public_buckets",
	}
	off := map[string]bool{}
	for cfnKey, name := range flags {
		v, set, ok := yamlBool(mapChild(cfg, cfnKey))
		switch {
		case set && !ok:
			return infra.Dynamic
		case !set || !v:
			off[name] = true
		}
	}
	return accessBlockValue(len(flags), off)
}

func cfnEncryption(props *yaml.Node) string {
	best := "none"
	for _, rule := range seqItems(mapChild(mapChild(props, "BucketEncryption"), "ServerSideEncryptionConfiguration")) {
		by := mapChild(rule, "ServerSideEncryptionByDefault")
		algo := cfnString(mapChild(by, "SSEAlgorithm"), "none")
		if algo == infra.Dynamic {
			return infra.Dynamic
		}
		if strings.HasPrefix(algo, "aws:kms") {
			algo = "aws:kms"
		}
		if algo == "aws:kms" || best == "none" {
			best = algo
		}
	}
	return best
}
