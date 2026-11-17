package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestPerlFlowEndToEnd exercises the whole Perl pipeline — lexctx → extractor →
// catalog → StructuralEngine — on small idiomatic snippets, asserting each
// dangerous flow fires its expected rule and each sanitized/constant counterpart
// does not. It is the integration guard that the pieces compose; the honest
// measured recall lives in testdata/precision-suite-perl.
func TestPerlFlowEndToEnd(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		rule     string
		wantFire bool
	}{
		// --- true positives: an untrusted source reaches a dangerous sink ---
		{"cmd_system_env", "my $h = $ENV{HOST};\nsystem(\"ping $h\");\n", "TAINT-002", true},
		{"cmd_system_parenless", "my $h = $ENV{HOST};\nsystem \"ping $h\";\n", "TAINT-002", true},
		{"cmd_backtick", "my $t = $ENV{T};\nmy $o = `traceroute $t`;\n", "TAINT-002", true},
		{"cmd_exec", "my $s = $ENV{S};\nexec(\"systemctl $s\");\n", "TAINT-002", true},
		{"cmd_argv", "my $x = $ARGV[0];\nsystem(\"echo $x\");\n", "TAINT-002", true},
		{"code_eval", "my $u = $ENV{U};\neval $u;\n", "TAINT-005", true},
		{"sqli_do", "my $id = $ENV{ID};\n$dbh->do(\"SELECT * FROM u WHERE id=$id\");\n", "TAINT-001", true},
		{"path_open", "my $f = $ENV{F};\nopen(my $fh, \"<\", $f);\n", "TAINT-004", true},
		{"ssrf_get", "my $url = $ENV{URL};\nmy $r = $ua->get($url);\n", "TAINT-006", true},
		{"cgi_param_cmd", "my $c = $q->param('cmd');\nsystem(\"echo $c\");\n", "TAINT-002", true},
		{"bare_param_cmd", "my $c = param('cmd');\nsystem(\"echo $c\");\n", "TAINT-002", true},
		{"stdin_cmd", "my $line = <STDIN>;\nsystem(\"echo $line\");\n", "TAINT-002", true},

		// --- true negatives: the sanitizer / safe form neutralizes the sink ---
		{"clean_int", "my $c = $ENV{C};\nmy $n = int($c);\nsystem(\"ping -c $n h\");\n", "TAINT-002", false},
		{"clean_quotemeta", "my $h = $ENV{H};\nmy $q = quotemeta($h);\nsystem(\"host $q\");\n", "TAINT-002", false},
		{"clean_placeholder", "my $id = $ENV{ID};\n$dbh->do(\"SELECT * FROM u WHERE id=?\", undef, $id);\n", "TAINT-001", false},
		{"clean_basename", "my $f = $ENV{F};\nmy $b = basename($f);\nopen(my $fh, \"<\", \"/srv/$b\");\n", "TAINT-004", false},
		{"clean_const_cmd", "system(\"systemctl status nginx\");\n", "TAINT-002", false},

		// --- scope: a fat-comma key is a string, and an anonymous sub is its
		// own scope (mojo t/mojolicious/embedded_lite_app.t). ---
		{"clean_fat_comma_key", "my $name = param('name');\nget('/bye' => {name => 'second'});\n", "TAINT-006", false},
		{"clean_handler_local_stays_in_handler",
			"get '/' => sub {\n  my $c = shift;\n  my $name = $c->param('name');\n  $c->render(text => \"Bye $name\");\n};\n\nget('/bye')->to(sub_name($name));\nmy $r = $ua->get($name);\n",
			"TAINT-006", false},
		{"clean_sub_ends_at_its_brace",
			"sub handler {\n  my $test = param('test');\n}\nmy $r = $ua->get($test);\n", "TAINT-006", false},
		{"fat_comma_value_still_read", "my $u = param('u');\nmy $r = $ua->get($u, timeout => 5);\n", "TAINT-006", true},
		{"anon_sub_body_still_analysed",
			"get '/f' => sub {\n  my $c = shift;\n  my $u = $c->param('u');\n  my $r = $ua->get($u);\n};\n", "TAINT-006", true},
		{"variable_before_fat_comma_still_read", "my $k = param('k');\nmy $r = $ua->get($k => 1);\n", "TAINT-006", true},
	}

	e := NewStructuralEngine(nil)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			units := ExtractUnits("sample.pl", lexctx.LangPerl, []byte(c.src))
			flows := e.AnalyzeFile(units)
			fired := false
			for i := range flows {
				if flows[i].Sink.RuleID == c.rule {
					fired = true
				}
			}
			if fired != c.wantFire {
				t.Errorf("%s: rule %s fired=%v, want %v (flows=%+v)", c.name, c.rule, fired, c.wantFire, flows)
			}
		})
	}
}
