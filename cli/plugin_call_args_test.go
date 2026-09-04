package main

import (
	"reflect"
	"testing"
)

// flag.FlagSet.Parse stops at the first non-flag argument, so with the order
// the usage string documents — `nox plugin call <name> <tool> --input f` — the
// flag was never parsed. It fell through to the key=value loop, where
// SplitN(kv, "=", 2) accepted "--input=f" as a key named "--input", and the
// tool ran with NO input at all while reporting success.
func TestInputFlagIsFoundAfterThePositionalArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"before positionals, separate", []string{"--input", "in.json", "p", "t"}, "in.json"},
		{"after positionals, separate", []string{"p", "t", "--input", "in.json"}, "in.json"},
		{"after positionals, joined", []string{"p", "t", "--input=in.json"}, "in.json"},
		{"single dash", []string{"p", "t", "-input=in.json"}, "in.json"},
		{"absent", []string{"p", "t", "k=v"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := extractInputFlag(tc.args)
			if err != nil {
				t.Fatalf("extractInputFlag: %v", err)
			}
			if got != tc.want {
				t.Errorf("inputFile = %q, want %q", got, tc.want)
			}
		})
	}
}

// A flag typo must not be swallowed as a key=value pair and become silent input.
func TestUnknownFlagIsRejectedRatherThanBecomingAnArgument(t *testing.T) {
	if _, _, err := extractInputFlag([]string{"p", "t", "--inpt=in.json"}); err == nil {
		t.Error("a misspelt flag was accepted; it would have become a tool argument named --inpt")
	}
	if _, _, err := extractInputFlag([]string{"p", "t", "--input"}); err == nil {
		t.Error("--input with no value was accepted")
	}
}

func TestPositionalsSurviveFlagExtraction(t *testing.T) {
	_, pos, err := extractInputFlag([]string{"nox/ai-eval", "ai_eval", "--input=in.json", "k=v"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"nox/ai-eval", "ai_eval", "k=v"}; !reflect.DeepEqual(pos, want) {
		t.Errorf("positional = %v, want %v", pos, want)
	}
}

// Every value used to be a string, so a tool input declared as a bool could not
// be satisfied from the command line at all. nox/ai-eval gates its attack
// corpus behind `authorize: true` and asserts req.Input["authorize"].(bool):
// authorize=true sent the string "true", the assertion failed, and the operator
// got a lecture about authorisation rather than a word about types.
func TestTypedArgumentsSendJSON(t *testing.T) {
	tests := []struct {
		arg  string
		key  string
		want any
	}{
		{"authorize:=true", "authorize", true},
		{"authorize:=false", "authorize", false},
		{"count:=42", "count", float64(42)},
		{"ratio:=1.5", "ratio", 1.5},
		{"opt:=null", "opt", nil},
		{`tags:=["a","b"]`, "tags", []any{"a", "b"}},
		{`cfg:={"k":1}`, "cfg", map[string]any{"k": float64(1)}},
		{`name:="literal"`, "name", "literal"},
	}
	for _, tc := range tests {
		t.Run(tc.arg, func(t *testing.T) {
			k, v, err := parseToolArg(tc.arg)
			if err != nil {
				t.Fatalf("parseToolArg(%q): %v", tc.arg, err)
			}
			if k != tc.key || !reflect.DeepEqual(v, tc.want) {
				t.Errorf("= (%q, %#v), want (%q, %#v)", k, v, tc.key, tc.want)
			}
		})
	}
}

// key= must keep sending a string unconditionally: inferring would make a tool
// that takes the literal string "true" impossible to call, and would change the
// meaning of arguments that work today.
func TestPlainArgumentsStayStrings(t *testing.T) {
	for _, arg := range []string{"authorize=true", "count=42", "opt=null", "name=hello"} {
		_, v, err := parseToolArg(arg)
		if err != nil {
			t.Fatalf("parseToolArg(%q): %v", arg, err)
		}
		if _, ok := v.(string); !ok {
			t.Errorf("%q produced %T, want string", arg, v)
		}
	}
}

func TestMalformedArgumentsAreRejected(t *testing.T) {
	for _, arg := range []string{"novalue", "=novalue", ":=true", "bad:=not-json"} {
		if _, _, err := parseToolArg(arg); err == nil {
			t.Errorf("parseToolArg(%q) accepted a malformed argument", arg)
		}
	}
}
