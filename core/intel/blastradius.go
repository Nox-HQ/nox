package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Blast radius asks the intelligence service what a vulnerability reaches in
// one organisation's estate. The service can only answer from what the
// organisation tells it: which components it deploys, what each can reach, and
// which exploit runs it made. This file builds those inputs from what nox
// established locally, and nothing else — every field is either derived from
// evidence the scan gathered or declared by the operator, and the two are never
// confused.
//
// Unlike an Observation, nothing here is anonymised: an inventory is sent
// authenticated, to the organisation's own private store, because describing
// your own estate to yourself is the point. It is never sent by a scan; only
// `nox intel components --upload` sends it.

// Component is one deployed dependency of one service, in the shape the
// intelligence service stores (nox-intelligence domain.Component).
type Component struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Version   string `json:"version,omitempty"`
	Service   string `json:"service"`
	// VulnerablePathReachable is set when the service's own source imports the
	// package. nox cannot know which symbols a candidate it has never seen
	// affects, so "the service's code uses this package" is the strongest
	// package-level reachability it can establish, and absence of an import is
	// NOT evidence the package is unused (it may be reached through another
	// dependency) — it only leaves the rung unclimbed.
	VulnerablePathReachable bool `json:"vulnerable_path_reachable"`
	// ExternallyExposed is the operator's declaration that the service accepts
	// untrusted input (--exposed), applied to the components its code imports.
	// nox does not infer it: whether a service is internet-facing is a fact
	// about the deployment, not the source.
	ExternallyExposed bool     `json:"externally_exposed"`
	Capabilities      []string `json:"capabilities,omitempty"`
	Identities        []string `json:"identities,omitempty"`
	DataClasses       []string `json:"data_classes,omitempty"`
}

// Package is a dependency as the scan inventoried it.
type Package struct {
	Ecosystem string
	Name      string
	Version   string
}

// SinkSite is a call in the service's own code to a sink the taint catalog
// knows, whatever reaches it.
type SinkSite struct {
	Class string `json:"class"`
	Call  string `json:"call"`
	File  string `json:"file"`
	Line  int    `json:"line"`
}

// DerivedCapability is a capability nox attributes to the service, with the
// call that establishes it.
type DerivedCapability struct {
	Capability string   `json:"capability"`
	Evidence   SinkSite `json:"evidence"`
}

// InventoryOptions is what the operator declares about the service.
type InventoryOptions struct {
	Service      string
	Exposed      bool
	Capabilities []string
	Identities   []string
	DataClasses  []string
}

// ServiceInventory is one service's components, with the evidence behind every
// derived capability so the output can be checked before anything is sent.
type ServiceInventory struct {
	Service    string              `json:"service"`
	Components []Component         `json:"components"`
	Derived    []DerivedCapability `json:"derived_capabilities,omitempty"`
}

// capabilityForClass maps a sink's vulnerability class to the authority calling
// it demonstrates. Deliberately the weaker reading where the call is
// ambiguous: a SQL call shows the service can read its database, and a file
// sink that it can read the filesystem, but neither shows it can write.
// Claiming more from a call than it shows would inflate every blast radius
// built on it; an operator who knows better adds the rest with --capability.
var capabilityForClass = map[string]string{
	"command_injection": "shell.execute",
	"code_injection":    "code.execute",
	"ssrf":              "network.egress",
	"sql_injection":     "database.read",
	"path_traversal":    "filesystem.read",
}

// namePattern is the service's own constraint on component ids and service
// names: printable, no whitespace, no path separators.
var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)

// capabilityPattern is the "domain.action" slug the service requires.
var capabilityPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

// ValidServiceName reports whether name is acceptable to the service.
func ValidServiceName(name string) bool { return namePattern.MatchString(name) }

// ServiceNameFrom derives a service name from a directory name, replacing what
// the service does not accept.
func ServiceNameFrom(dir string) string {
	s := sanitize(dir)
	s = strings.TrimLeft(s, "._:@-")
	if s == "" {
		return "service"
	}
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

// BuildServiceInventory turns the scan's packages into the service's
// components.
//
// imports answers whether the service's source imports a package (nil means
// no import information). sites are the sink calls in the service's source;
// their capabilities, with the operator's, apply to every component, because a
// dependency runs inside the service's process and holds whatever the process
// holds.
func BuildServiceInventory(pkgs []Package, imports func(ecosystem, name string) bool,
	sites []SinkSite, opts InventoryOptions) (*ServiceInventory, error) {
	if !ValidServiceName(opts.Service) {
		return nil, fmt.Errorf("service %q must be 1-128 characters of letters, digits and . _ : @ -", opts.Service)
	}
	for _, c := range opts.Capabilities {
		if !capabilityPattern.MatchString(c) {
			return nil, fmt.Errorf("capability %q is not a domain.action slug (e.g. secret.read)", c)
		}
	}
	for _, list := range [][]string{opts.Identities, opts.DataClasses} {
		for _, v := range list {
			if strings.TrimSpace(v) == "" || len(v) > 256 {
				return nil, fmt.Errorf("identities and data classes must be non-empty and at most 256 characters")
			}
		}
	}

	derived := deriveCapabilities(sites)
	caps := map[string]bool{}
	for _, d := range derived {
		caps[d.Capability] = true
	}
	for _, c := range opts.Capabilities {
		caps[c] = true
	}
	capList := sortedKeys(caps)

	seen := map[string]bool{}
	out := &ServiceInventory{Service: opts.Service, Derived: derived, Components: []Component{}}
	for _, p := range pkgs {
		if strings.TrimSpace(p.Ecosystem) == "" || strings.TrimSpace(p.Name) == "" {
			continue
		}
		id := componentID(opts.Service, p)
		if seen[id] {
			continue // the same package found in two manifests is one component
		}
		seen[id] = true
		imported := imports != nil && imports(p.Ecosystem, p.Name)
		out.Components = append(out.Components, Component{
			ID:                      id,
			Ecosystem:               p.Ecosystem,
			Package:                 p.Name,
			Version:                 p.Version,
			Service:                 opts.Service,
			VulnerablePathReachable: imported,
			ExternallyExposed:       opts.Exposed && imported,
			Capabilities:            capList,
			Identities:              sortedUnique(opts.Identities),
			DataClasses:             sortedUnique(opts.DataClasses),
		})
	}
	sort.Slice(out.Components, func(i, j int) bool { return out.Components[i].ID < out.Components[j].ID })
	return out, nil
}

// deriveCapabilities keeps one site per capability — the first by class, call,
// file and line — as its evidence.
func deriveCapabilities(sites []SinkSite) []DerivedCapability {
	ordered := append([]SinkSite(nil), sites...)
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		if a.Call != b.Call {
			return a.Call < b.Call
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	byCap := map[string]SinkSite{}
	for _, s := range ordered {
		c, ok := capabilityForClass[s.Class]
		if !ok {
			continue
		}
		if _, have := byCap[c]; !have {
			byCap[c] = s
		}
	}
	out := make([]DerivedCapability, 0, len(byCap))
	for _, c := range sortedKeys(boolSet(byCap)) {
		out = append(out, DerivedCapability{Capability: c, Evidence: byCap[c]})
	}
	return out
}

// componentID is stable and readable: service, ecosystem, package and version,
// with anything the service does not accept replaced. When replacement or
// truncation changed the name, a hash of the original is appended so two
// packages that sanitise alike ("@types/node" and "_types_node") stay two ids.
func componentID(service string, p Package) string {
	raw := service + ":" + p.Ecosystem + ":" + p.Name + "@" + p.Version
	clean := sanitize(raw)
	if clean == raw && len(clean) <= 128 {
		return clean
	}
	sum := sha256.Sum256([]byte(raw))
	suffix := "-" + hex.EncodeToString(sum[:])[:10]
	if len(clean) > 128-len(suffix) {
		clean = clean[:128-len(suffix)]
	}
	return clean + suffix
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == ':', r == '@', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func boolSet[V any](m map[string]V) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, s := range in {
		set[strings.TrimSpace(s)] = true
	}
	return sortedKeys(set)
}

// ExploitEvidence is one `nox attack` run bound to an intelligence candidate,
// in the shape the service stores (nox-intelligence domain.ExploitEvidence).
type ExploitEvidence struct {
	TraceID        string `json:"trace_id"`
	Fingerprint    string `json:"fingerprint"`
	ComponentID    string `json:"component_id,omitempty"`
	Exploitability string `json:"exploitability"`
	Deterministic  bool   `json:"deterministic"`
	Reproduced     bool   `json:"reproduced"`
	ObservedAt     string `json:"observed_at"`
}

// fingerprintPattern is a full candidate fingerprint as the service keys it.
var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidCandidateFingerprint reports whether fp names a candidate the way the
// service does: 64 lowercase hex characters.
func ValidCandidateFingerprint(fp string) bool { return fingerprintPattern.MatchString(fp) }

// ValidComponentID reports whether id is acceptable as a component id.
func ValidComponentID(id string) bool { return namePattern.MatchString(id) }
