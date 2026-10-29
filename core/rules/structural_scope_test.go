package rules

import "testing"

// TestFileScopeParsesOnce: the scope ScanFile keeps for a file hands every
// structural rule the same parsed document, and no scope parses each time.
func TestFileScopeParsesOnce(t *testing.T) {
	content := []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: c\n    image: x\n")
	var scope fileScope
	first := scope.structuralDoc(content)
	if second := scope.structuralDoc(content); second != first {
		t.Error("a file scope parsed the file again")
	}
	var none *fileScope
	a := none.structuralDoc(content)
	if b := none.structuralDoc(content); a == b {
		t.Error("without a scope, two calls shared a parse")
	}
}
