package engine

import (
	"reflect"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// Cross-method flow through an INSTANCE FIELD: the source lands in a field in
// one method and a sink in another reads it. Fields declared in the class body
// are the syntactically shared names, and they are shared within their class —
// a same-named field of another class is a different variable.
func TestDartInstanceFieldJoinsMethods(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"field set in configure, read in run", `import 'dart:io';
class Fetcher {
  String target = '';

  void configure() {
    target = Platform.environment['TARGET'] ?? '';
  }

  Future<void> run(HttpClient client) async {
    final req = await client.getUrl(Uri.parse(target));
    await req.close();
  }
}
`, []string{"TAINT-006"}},
		{"this. on both sides", `import 'dart:io';
class Fetcher {
  late String target;

  void configure() {
    this.target = Platform.environment['TARGET'] ?? '';
  }

  Future<void> run(HttpClient client) async {
    final req = await client.getUrl(Uri.parse(this.target));
    await req.close();
  }
}
`, []string{"TAINT-006"}},
		{"top-level variable", `import 'dart:io';
String target = '';

void configure() {
  target = Platform.environment['TARGET'] ?? '';
}

Future<void> run(HttpClient client) async {
  final req = await client.getUrl(Uri.parse(target));
  await req.close();
}
`, []string{"TAINT-006"}},
		{"field holds a constant", `import 'dart:io';
class Fetcher {
  String target = '';

  void configure() {
    target = 'https://example.com/';
  }

  Future<void> run(HttpClient client) async {
    final req = await client.getUrl(Uri.parse(target));
    await req.close();
  }
}
`, nil},
		{"another class's same-named field", `import 'dart:io';
class Config {
  String target = '';
  void load() {
    target = Platform.environment['TARGET'] ?? '';
  }
}

class Fetcher {
  String target = 'https://example.com/';
  Future<void> run(HttpClient client) async {
    final req = await client.getUrl(Uri.parse(target));
    await req.close();
  }
}
`, nil},
		{"a local of the same name is not the field", `import 'dart:io';
class Fetcher {
  String target = '';

  void configure() {
    target = Platform.environment['TARGET'] ?? '';
  }

  Future<void> run(HttpClient client) async {
    final target = 'https://example.com/';
    final req = await client.getUrl(Uri.parse(target));
    await req.close();
  }
}
`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := analyzeRuleIDs(t, "t.dart", lexctx.LangDart, tc.src)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rules = %v, want %v", got, tc.want)
			}
		})
	}
}

// Taint laundered through a CONTAINER: `list.add(tainted)` mutates the list,
// so a later element read carries the taint (container-level, like an element
// assignment `list[0] = tainted`).
func TestDartContainerMutatorBinds(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"list.add then element read", `import 'dart:io';
Future<void> fetchFirst(HttpClient client) async {
  final urls = <String>[];
  urls.add(Platform.environment['TARGET'] ?? '');
  final req = await client.getUrl(Uri.parse(urls[0]));
  await req.close();
}
`, []string{"TAINT-006"}},
		{"element assignment", `import 'dart:io';
Future<void> fetchFirst(HttpClient client) async {
  final urls = <String, String>{};
  urls['a'] = Platform.environment['TARGET'] ?? '';
  final req = await client.getUrl(Uri.parse(urls['a']!));
  await req.close();
}
`, []string{"TAINT-006"}},
		{"constant added", `import 'dart:io';
Future<void> fetchFirst(HttpClient client) async {
  final urls = <String>[];
  urls.add('https://example.com/');
  final req = await client.getUrl(Uri.parse(urls[0]));
  await req.close();
}
`, nil},
		{"tainted value added to an unrelated list", `import 'dart:io';
Future<void> fetchFirst(HttpClient client) async {
  final urls = <String>['https://example.com/'];
  final log = <String>[];
  log.add(Platform.environment['TARGET'] ?? '');
  final req = await client.getUrl(Uri.parse(urls[0]));
  await req.close();
}
`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := analyzeRuleIDs(t, "t.dart", lexctx.LangDart, tc.src)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rules = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDartDeclaredName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"String target = '';", "target"},
		{"late String target;", "target"},
		{"static final List<String> urls = <String>[];", "urls"},
		{"final Dio dio = Dio();", "dio"},
		{"Map<String, String> headers = {};", "headers"},
		{"target = e;", ""},
		{"Fetcher(this.target);", ""},
		{"String get target => _target;", ""},
		{"String f(String x) => x;", ""},
		{"bool same = a == b;", "same"},
	}
	for _, tc := range cases {
		got, ok := dartDeclaredName(tc.in)
		if !ok {
			got = ""
		}
		if got != tc.want {
			t.Errorf("dartDeclaredName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestBlankDartThis(t *testing.T) {
	ll := blankDartThis(logicalLine{code: "this.target = f(this.x, isthis.y)"})
	if want := "     target = f(     x, isthis.y)"; ll.code != want {
		t.Fatalf("code = %q, want %q", ll.code, want)
	}
}
