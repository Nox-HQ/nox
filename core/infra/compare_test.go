package infra

import (
	"strings"
	"testing"
)

func res(kind, name, file string, props map[string]string) Resource {
	return Resource{Kind: kind, Name: name, File: file, Properties: props}
}

func inv(rs ...Resource) *Inventory {
	i := &Inventory{Resources: rs}
	i.Normalize()
	return i
}

func only(t *testing.T, changes []Change) Change {
	t.Helper()
	if len(changes) != 1 {
		t.Fatalf("want exactly one change, got %d: %+v", len(changes), changes)
	}
	return changes[0]
}

func TestCompareWordsTheInvalidatedAssumption(t *testing.T) {
	prev := inv(res("aws_s3_bucket", "uploads", "deploy/tf/main.tf", map[string]string{"public_access_block": "all true"}))
	cur := inv(res("aws_s3_bucket", "uploads", "deploy/tf/main.tf", map[string]string{"public_access_block": "all false"}))
	c := only(t, Compare(prev, cur))
	want := "aws_s3_bucket.uploads (deploy/tf/main.tf): public access block — was all true, now all false"
	if c.Line() != want || c.Direction != Weaker {
		t.Errorf("got %q (%s), want %q (weaker)", c.Line(), c.Direction, want)
	}
}

func TestComparePropertyDirections(t *testing.T) {
	cases := []struct {
		name, kind, prop, from, to, dir string
	}{
		{"privileged on", "Deployment", "privileged", "false", "true", Weaker},
		{"privileged off", "Deployment", "privileged", "true", "false", Stronger},
		{"hostNetwork on", "Deployment", "host_network", "false", "true", Weaker},
		{"runAsUser 0", "Deployment", "run_as_user", "10001", "0", Weaker},
		{"runAsUser unset to set", "Deployment", "run_as_user", "unset", "1000", Stronger},
		{"runAsNonRoot off", "Deployment", "run_as_non_root", "true", "false", Weaker},
		{"SYS_ADMIN added", "Deployment", "capabilities_added", "none", "SYS_ADMIN", Weaker},
		{"harmless capability still weaker than none", "Deployment", "capabilities_added", "none", "NET_BIND_SERVICE", Weaker},
		{"dangerous capability dropped", "Deployment", "capabilities_added", "SYS_ADMIN", "NET_BIND_SERVICE", Stronger},
		{"second dangerous capability", "Deployment", "capabilities_added", "SYS_ADMIN", "NET_ADMIN, SYS_ADMIN", Weaker},
		{"seccomp unconfined", "Deployment", "seccomp", "RuntimeDefault", "Unconfined", Weaker},
		{"privilege escalation allowed", "Deployment", "allow_privilege_escalation", "false", "true", Weaker},
		{"read-only fs lost", "Deployment", "read_only_root_fs", "true", "false", Weaker},
		{"token automounted", "Deployment", "automount_sa_token", "false", "true", Weaker},
		{"image unpinned", "Deployment", "image_pin", "digest", "unpinned", Weaker},
		{"image pinned to tag", "Deployment", "image_pin", "unpinned", "tag", Stronger},
		{"secret became literal", "Deployment", "env.DB_PASSWORD", "secretKeyRef", "literal", Weaker},
		{"literal became secret", "Deployment", "env.DB_PASSWORD", "literal", "secretKeyRef", Stronger},
		{"TLS removed", "Ingress", "tls", "all hosts", "none", Weaker},
		{"TLS partial", "Ingress", "tls", "all hosts", "partial", Weaker},
		{"redirect off", "Ingress", "ssl_redirect", "true", "false", Weaker},
		{"bucket made public", "aws_s3_bucket", "acl", "private", "public-read", Weaker},
		{"bucket made private", "aws_s3_bucket", "acl", "public-read", "private", Stronger},
		{"one flag off", "aws_s3_bucket", "public_access_block", "all true", "partial (false: block_public_acls)", Weaker},
		{"block removed", "aws_s3_bucket", "public_access_block", "all true", "absent", Weaker},
		{"block restored", "aws_s3_bucket", "public_access_block", "all false", "all true", Stronger},
		{"encryption dropped", "aws_s3_bucket", "encryption", "aws:kms", "none", Weaker},
		{"kms over aes", "aws_s3_bucket", "encryption", "AES256", "aws:kms", Stronger},
		{"database made public", "aws_db_instance", "publicly_accessible", "false", "true", Weaker},
		{"database unencrypted", "aws_db_instance", "storage_encrypted", "true", "false", Weaker},
		{"security group opened", "aws_security_group", "open_to_world", "false", "true", Weaker},
		{"USER dropped", "Dockerfile", "user", "node", "root (no USER)", Weaker},
		{"USER added", "Dockerfile", "user", "root (no USER)", "node", Stronger},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := only(t, Compare(
				inv(res(tc.kind, "x", "f", map[string]string{tc.prop: tc.from})),
				inv(res(tc.kind, "x", "f", map[string]string{tc.prop: tc.to})),
			))
			if c.Direction != tc.dir {
				t.Errorf("%s -> %s: direction %s, want %s", tc.from, tc.to, c.Direction, tc.dir)
			}
		})
	}
}

func TestCompareSaysNothingItCannotSay(t *testing.T) {
	same := map[string]string{"privileged": "false"}
	cases := []struct {
		name      string
		prev, cur *Inventory
	}{
		{"no change", inv(res("Deployment", "w", "f", same)), inv(res("Deployment", "w", "f", same))},
		{"a value that cannot be evaluated is not a change", inv(res("aws_db_instance", "d", "f", map[string]string{"publicly_accessible": "false"})),
			inv(res("aws_db_instance", "d", "f", map[string]string{"publicly_accessible": Dynamic}))},
		{"a property the earlier inventory did not record", inv(res("Deployment", "w", "f", nil)),
			inv(res("Deployment", "w", "f", map[string]string{"privileged": "true"}))},
		{"a property that is no longer recorded", inv(res("Deployment", "w", "f", map[string]string{"privileged": "true"})),
			inv(res("Deployment", "w", "f", nil))},
		{"context that is not ranked", inv(res("aws_security_group", "g", "f", map[string]string{"ingress_cidrs": "10.0.0.0/8"})),
			inv(res("aws_security_group", "g", "f", map[string]string{"ingress_cidrs": "10.0.0.0/8, 0.0.0.0/0"}))},
		{"a resource that is new is not a property change", inv(), inv(res("Deployment", "w", "f", map[string]string{"privileged": "true"}))},
		{"a resource that is gone is not a property change", inv(res("Deployment", "w", "f", map[string]string{"privileged": "true"})), inv()},
		{"the same name in another file is another resource", inv(res("Deployment", "w", "a.yaml", map[string]string{"privileged": "false"})),
			inv(res("Deployment", "w", "b.yaml", map[string]string{"privileged": "true"}))},
		{"two values of one rank", inv(res("Deployment", "w", "f", map[string]string{"run_as_user": "1000"})),
			inv(res("Deployment", "w", "f", map[string]string{"run_as_user": "2000"}))},
		{"no earlier inventory", nil, inv(res("Deployment", "w", "f", same))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Compare(tc.prev, tc.cur); len(got) != 0 {
				t.Errorf("want no change, got %+v", got)
			}
		})
	}
}

// Lines are presentation: a resource that moved within its file is unchanged.
func TestCompareIgnoresLines(t *testing.T) {
	a := res("Deployment", "w", "f", map[string]string{"privileged": "false"})
	b := a
	a.Line, b.Line = 3, 40
	if got := Compare(inv(a), inv(b)); len(got) != 0 {
		t.Errorf("a move reported %+v", got)
	}
	// And a resource that moved AND changed is still the same resource: the
	// change is found, not mistaken for a removal plus an addition.
	b.Properties = map[string]string{"privileged": "true"}
	only(t, Compare(inv(a), inv(b)))
}

func TestCompareOrderIsStable(t *testing.T) {
	prev := inv(
		res("Deployment", "b", "z.yaml", map[string]string{"privileged": "false", "host_network": "false", "env.TOKEN": "secretKeyRef"}),
		res("Deployment", "a", "a.yaml", map[string]string{"privileged": "false"}),
	)
	cur := inv(
		res("Deployment", "b", "z.yaml", map[string]string{"privileged": "true", "host_network": "true", "env.TOKEN": "literal"}),
		res("Deployment", "a", "a.yaml", map[string]string{"privileged": "true"}),
	)
	var order []string
	for _, c := range Compare(prev, cur) {
		order = append(order, c.File+":"+c.Property)
	}
	want := "a.yaml:privileged z.yaml:privileged z.yaml:host_network z.yaml:env.TOKEN"
	if got := strings.Join(order, " "); got != want {
		t.Errorf("order = %s, want %s", got, want)
	}
}

func TestEnvLabelAndWording(t *testing.T) {
	c := only(t, Compare(
		inv(res("Deployment", "web", "k.yaml", map[string]string{"env.DB_PASSWORD": "secretKeyRef"})),
		inv(res("Deployment", "web", "k.yaml", map[string]string{"env.DB_PASSWORD": "literal"})),
	))
	want := "Deployment web (k.yaml): env DB_PASSWORD — was secretKeyRef, now a literal value"
	if c.Line() != want {
		t.Errorf("got %q, want %q", c.Line(), want)
	}
}

func TestNormalizeSeparatesDuplicateIdentities(t *testing.T) {
	i := inv(res("Deployment", "w", "f", nil), res("Deployment", "w", "f", nil))
	if len(i.Index()) != 2 {
		t.Errorf("duplicates collapsed: %+v", i.Resources)
	}
}
