package infra

import (
	"sort"
	"strings"
)

// Direction says which way a property moved.
const (
	Weaker   = "weaker"
	Stronger = "stronger"
)

// Dynamic is the value recorded for a property nox could see but not evaluate:
// a variable, a template, a reference. It is never compared, because "was
// false, now var.public" is not a statement about the system.
const Dynamic = "dynamic"

// Change is one property of one resource that moved between two inventories.
type Change struct {
	Resource  string `json:"resource"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	File      string `json:"file"`
	Class     string `json:"class"`
	Property  string `json:"property"`
	Label     string `json:"label"`
	From      string `json:"from"`
	To        string `json:"to"`
	Direction string `json:"direction"`
}

// Line renders the change as one sentence:
//
//	aws_s3_bucket.uploads (deploy/tf/main.tf): public access block - was all true, now false
func (c Change) Line() string {
	return c.Resource + " (" + c.File + "): " + c.Label + " — was " + displayValue(c.Property, c.From) +
		", now " + displayValue(c.Property, c.To)
}

// ranker orders the values of one property from weakest (lowest) to strongest.
// ok is false for a value it cannot place, which excludes the pair from any
// comparison.
type ranker func(v string) (rank int, ok bool)

type propSpec struct {
	label string
	rank  ranker
}

// order is the order properties are listed in, so output does not depend on map
// iteration.
var order = []string{
	"public_access_block", "acl", "encryption",
	"publicly_accessible", "storage_encrypted", "open_to_world",
	"tls", "ssl_redirect",
	"privileged", "host_network", "host_pid", "host_ipc", "run_as_non_root", "run_as_user",
	"allow_privilege_escalation", "read_only_root_fs", "capabilities_added", "capabilities_drop_all",
	"seccomp", "automount_sa_token", "image_pin", "user",
}

func enum(values ...string) ranker {
	return func(v string) (int, bool) {
		for i, x := range values {
			if v == x {
				return i, true
			}
		}
		return 0, false
	}
}

var catalogue = map[string]propSpec{
	"public_access_block":        {"public access block", rankAccessBlock},
	"acl":                        {"ACL", rankACL},
	"encryption":                 {"default encryption", enum("none", "AES256", "aws:kms")},
	"publicly_accessible":        {"publicly accessible", enum("true", "false")},
	"storage_encrypted":          {"storage encrypted", enum("false", "true")},
	"open_to_world":              {"open to the internet", enum("true", "false")},
	"tls":                        {"TLS", enum("none", "partial", "all hosts")},
	"ssl_redirect":               {"ssl-redirect", enum("false", "unset", "true")},
	"privileged":                 {"privileged", enum("true", "false")},
	"host_network":               {"hostNetwork", enum("true", "false")},
	"host_pid":                   {"hostPID", enum("true", "false")},
	"host_ipc":                   {"hostIPC", enum("true", "false")},
	"run_as_non_root":            {"runAsNonRoot", enum("false", "unset", "true")},
	"run_as_user":                {"runAsUser", rankRunAsUser},
	"allow_privilege_escalation": {"allowPrivilegeEscalation", enum("true", "false")},
	"read_only_root_fs":          {"readOnlyRootFilesystem", enum("false", "true")},
	"capabilities_added":         {"added capabilities", rankCapabilities},
	"capabilities_drop_all":      {"drops ALL capabilities", enum("false", "true")},
	"seccomp":                    {"seccomp profile", rankSeccomp},
	"automount_sa_token":         {"automounted service account token", enum("true", "false")},
	"image_pin":                  {"image pinning", enum("unpinned", "tag", "digest")},
	"user":                       {"container user", rankUser},
}

// envPrefix starts the key of a credential-named environment variable.
const envPrefix = "env."

// specFor returns the specification of a property key.
func specFor(key string) (propSpec, bool) {
	if name, ok := strings.CutPrefix(key, envPrefix); ok {
		return propSpec{label: "env " + name, rank: rankEnvSource}, true
	}
	s, ok := catalogue[key]
	return s, ok
}

// Label is the plain-language name of a property key.
func Label(key string) string {
	if s, ok := specFor(key); ok {
		return s.label
	}
	return key
}

// Rank places a value of a property on its weakest-to-strongest scale. ok is
// false when the property has no scale or the value cannot be placed.
func Rank(key, value string) (rank int, ok bool) {
	spec, found := specFor(key)
	if !found {
		return 0, false
	}
	return spec.rank(value)
}

// Ranked reports whether a property can be compared at all.
func Ranked(key string) bool {
	_, ok := specFor(key)
	return ok
}

func rankAccessBlock(v string) (int, bool) {
	switch {
	case v == "all true":
		return 4, true
	case v == "all false", v == "absent":
		return 0, true
	case strings.HasPrefix(v, "partial (false: "):
		n := strings.Count(v, ",") + 1
		return 4 - n, true
	}
	return 0, false
}

func rankACL(v string) (int, bool) {
	switch {
	case v == Dynamic:
		return 0, false
	case strings.HasPrefix(v, "public"), v == "authenticated-read":
		return 0, true
	}
	return 1, true
}

func rankRunAsUser(v string) (int, bool) {
	switch v {
	case "0":
		return 0, true
	case "unset":
		return 1, true
	case Dynamic:
		return 0, false
	}
	return 2, true
}

// dangerousCapabilities are the capabilities whose presence widens what a
// container can do to the host.
var dangerousCapabilities = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "NET_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true,
	"SYS_RAWIO": true, "DAC_READ_SEARCH": true, "DAC_OVERRIDE": true, "BPF": true, "SYS_BOOT": true,
	"NET_RAW": true, "SYS_TIME": true, "MKNOD": true, "SETUID": true, "SETGID": true,
}

func rankCapabilities(v string) (int, bool) {
	if v == Dynamic {
		return 0, false
	}
	if v == "none" {
		return 0, true
	}
	score := 0
	for _, c := range strings.Split(v, ", ") {
		if dangerousCapabilities[c] {
			score -= 10
		} else {
			score--
		}
	}
	return score, true
}

func rankSeccomp(v string) (int, bool) {
	switch v {
	case "Unconfined":
		return 0, true
	case "unset":
		return 1, true
	case "RuntimeDefault", "Localhost":
		return 2, true
	}
	return 0, false
}

func rankUser(v string) (int, bool) {
	if v == Dynamic {
		return 0, false
	}
	if strings.HasPrefix(v, "root") {
		return 0, true
	}
	return 1, true
}

func rankEnvSource(v string) (int, bool) {
	switch v {
	case "literal":
		return 0, true
	case "configMapKeyRef":
		return 0, true
	case "variable", "valueFrom":
		return 1, true
	case "secretKeyRef", "secret":
		return 2, true
	}
	return 0, false
}

// displayValue words a stored value for a sentence.
func displayValue(key, v string) string {
	if strings.HasPrefix(key, envPrefix) && v == "literal" {
		return "a literal value"
	}
	return v
}

// Compare returns the properties that moved between prev and cur on resources
// present in both. A resource in only one of them is added or removed, which is
// not a property changing and is reported elsewhere. A property recorded on
// only one side, or whose value either side could not evaluate, is not
// compared. Identity is the resource ID, which carries no line number, so a
// resource that only moved is unchanged.
func Compare(prev, cur *Inventory) []Change {
	if prev == nil || cur == nil {
		return nil
	}
	pidx := prev.Index()
	var out []Change
	for _, r := range cur.Resources {
		old, ok := pidx[r.ID()]
		if !ok {
			continue
		}
		for _, key := range propertyKeys(r.Properties) {
			was, had := old.Properties[key]
			now := r.Properties[key]
			if !had || was == now {
				continue
			}
			spec, ok := specFor(key)
			if !ok {
				continue
			}
			wr, wok := spec.rank(was)
			nr, nok := spec.rank(now)
			if !wok || !nok || wr == nr {
				continue
			}
			dir := Stronger
			if nr < wr {
				dir = Weaker
			}
			out = append(out, Change{
				Resource: r.Display(), Kind: r.Kind, Name: r.Name, Namespace: r.Namespace, File: r.File,
				Class: r.Class, Property: key, Label: spec.label, From: was, To: now, Direction: dir,
			})
		}
	}
	sortChanges(out)
	return out
}

func propertyKeys(p map[string]string) []string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func propertyIndex(key string) int {
	if strings.HasPrefix(key, envPrefix) {
		return len(order)
	}
	for i, k := range order {
		if k == key {
			return i
		}
	}
	return len(order) + 1
}

func sortChanges(c []Change) {
	sort.SliceStable(c, func(i, j int) bool {
		a, b := c[i], c[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		if pa, pb := propertyIndex(a.Property), propertyIndex(b.Property); pa != pb {
			return pa < pb
		}
		return a.Property < b.Property
	})
}

// Split separates the changes that weakened an assumption from those that
// strengthened one.
func Split(changes []Change) (weaker, stronger []Change) {
	for _, c := range changes {
		if c.Direction == Weaker {
			weaker = append(weaker, c)
		} else {
			stronger = append(stronger, c)
		}
	}
	return weaker, stronger
}
