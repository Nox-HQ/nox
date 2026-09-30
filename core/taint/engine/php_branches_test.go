package engine

import (
	"strings"
	"testing"
)

// phpCase is one PHP source and the rule IDs it must report (nil: none).
type phpCase struct {
	name string
	src  string
	want []string
}

func runPHPCases(t *testing.T, cases []phpCase) {
	t.Helper()
	for _, c := range cases {
		got := analyzePHPFile(t, c.src)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestPHPBranchModel: an assignment in one arm is a weak update, and a
// constant condition is resolved.
func TestPHPBranchModel(t *testing.T) {
	runPHPCases(t, []phpCase{
		{"else arm resets, the other keeps", `<?php
$t = $_GET['id'];
if (preg_match("/^.*$/", $t) == 1) {
  $t = $t;
} else {
  $t = "";
}
mysql_query("SELECT * FROM '" . $t . "'");
`, []string{"TAINT-001"}},
		{"elseif keyword", `<?php
$t = $_GET['id'];
if ($a) {
  $t = "x";
} elseif ($b) {
  $t = "y";
}
mysql_query("SELECT " . $t);
`, []string{"TAINT-001"}},
		{"constant condition takes the safe arm", `<?php
$t = $_GET['id'];
if (7 * 42 - 86 > 200) {
  $t = "safe";
} else {
  $t = $t;
}
mysql_query("SELECT " . $t);
`, nil},
		{"literal-only ternary", `<?php
$t = $_GET['id'];
$t = $t == 'safe1' ? 'safe1' : 'safe2';
mysql_query("SELECT '" . $t . "'");
`, nil},
		{"ternary with a tainted arm", `<?php
$t = $_GET['id'];
$u = $t != '' ? $t : 'none';
mysql_query("SELECT '" . $u . "'");
`, []string{"TAINT-001"}},
	})
}

// TestPHPInterpolationAndReceivers: interpolated variables are reads, and a
// database handle made by new mysqli / new PDO is the catalog's receiver.
func TestPHPInterpolationAndReceivers(t *testing.T) {
	runPHPCases(t, []phpCase{
		{"interpolated into the query", `<?php
$t = $_GET['id'];
$q = "SELECT * FROM t WHERE id = '$t'";
mysql_query($q);
`, []string{"TAINT-001"}},
		{"braced interpolation", `<?php
$t = $_POST['name'];
echo "<p>{$t}</p>";
`, []string{"TAINT-003"}},
		{"single quotes do not interpolate", `<?php
$t = $_GET['id'];
$q = 'SELECT * FROM t WHERE id = $t';
mysql_query($q);
`, nil},
		{"mysqli handle under another name", `<?php
$conn = new mysqli("h", "u", "p", "d");
$conn->query("SELECT * FROM t WHERE id = " . $_GET['id']);
`, []string{"TAINT-001"}},
		{"PDO handle under another name", `<?php
$db = new PDO("mysql:host=h");
$id = $_GET['id'];
$db->query("SELECT * FROM t WHERE id = $id");
`, []string{"TAINT-001"}},
		{"SimpleXML xpath", `<?php
$xml = simplexml_load_file("users.xml");
$u = $_GET['user'];
$xml->xpath("//user[@name='" . $u . "']");
`, []string{"TAINT-008"}},
		{"ldap_search filter", `<?php
$ds = ldap_connect("localhost");
$f = "(uid=" . $_GET['uid'] . ")";
ldap_search($ds, "dc=example,dc=com", $f);
`, []string{"TAINT-009"}},
	})
}

// TestPHPNumericConversion: a value converted to a number carries no
// injection; a number concatenated with a string still does.
func TestPHPNumericConversion(t *testing.T) {
	sink := "\nmysql_query(\"SELECT * FROM t WHERE id = \" . $t);\n"
	runPHPCases(t, []phpCase{
		{"int cast", "<?php\n$t = $_GET['id'];\n$t = (int) $t;" + sink, nil},
		{"float cast", "<?php\n$t = $_GET['id'];\n$t = (float)$t;" + sink, nil},
		{"arithmetic update", "<?php\n$t = $_GET['id'];\n$t += 0;" + sink, nil},
		{"arithmetic assign", "<?php\n$t = $_GET['id'];\n$t = $t + 0;" + sink, nil},
		{"settype statement", "<?php\n$t = $_GET['id'];\nsettype($t, \"integer\");" + sink, nil},
		{"settype in a condition", "<?php\n$t = $_GET['id'];\nif (settype($t, \"float\"))\n  $t = $t;\nelse\n  $t = 0.0;" + sink, nil},
		{"filter_var number", "<?php\n$t = $_GET['id'];\n$t = filter_var($t, FILTER_SANITIZE_NUMBER_INT);" + sink, nil},
		{"filter_var email is not numeric", "<?php\n$t = $_GET['id'];\n$t = filter_var($t, FILTER_SANITIZE_EMAIL);" + sink, []string{"TAINT-001"}},
		{"cast then concatenated", "<?php\n$t = $_GET['id'];\n$t = (int) $t . $_GET['x'];" + sink, []string{"TAINT-001"}},
		{"concatenation is not arithmetic", "<?php\n$t = $_GET['id'];\n$t = $t . 0;" + sink, []string{"TAINT-001"}},
	})
}

// TestPHPContainersGettersAndNames: array stores, a helper that returns a
// source, and variables whose names are keywords elsewhere.
func TestPHPContainersGettersAndNames(t *testing.T) {
	sink := "\nmysql_query(\"SELECT \" . $t);\n"
	runPHPCases(t, []phpCase{
		{"array element store", "<?php\n$a = array();\n$a['k'] = $_GET['x'];\n$t = $a['k'];" + sink, []string{"TAINT-001"}},
		{"array append", "<?php\n$a = array();\n$a[] = 'safe';\n$a[] = $_GET['x'];\n$t = $a[1];" + sink, []string{"TAINT-001"}},
		{"getter returns a source", "<?php\nfunction input() {\n  return $_GET['x'];\n}\n$t = input();" + sink, []string{"TAINT-001"}},
		{"method getter returns a source", "<?php\nclass In {\n  public function fetch() {\n    return $_POST['x'];\n  }\n}\n$o = new In();\n$t = $o->fetch();" + sink, []string{"TAINT-001"}},
		{"getter returns a constant", "<?php\nfunction input() {\n  return 'fixed';\n}\n$t = input();" + sink, nil},
		{"variable named string", "<?php\n$string = $_POST['x'];\n$t = $string;" + sink, []string{"TAINT-001"}},
		{"variable named type", "<?php\n$type = $_GET['t'];\n$t = \"SELECT * FROM $type\";" + sink, []string{"TAINT-001"}},
	})
}
