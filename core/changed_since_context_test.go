package core

import (
	"testing"
)

// A PR-scoped scan reports on the files the PR changed, but judges them
// against the tree: the requirements.txt that declares flask was not changed
// by the PR that edited the flask import, and SLOP-001 reported flask as
// undeclared on PR #1082. The second import is genuinely undeclared and must
// still be reported, so the test cannot pass by silencing the rule.
func TestChangedSinceReadsDeclarationsFromTheTree(t *testing.T) {
	dir := initGitRepo(t, map[string]string{
		"app/requirements.txt": "flask\n",
		"app/safe.py":          "from flask import Flask\n",
	})
	addCommit(t, dir, "edit the import", map[string]string{
		"app/safe.py": "from flask import Flask, jsonify\nimport flaskk_utils\n",
	})

	result, err := RunScanWithOptions(dir, ScanOptions{ChangedSince: "HEAD~1", Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range result.Findings.Findings() {
		if f.RuleID == "SLOP-001" {
			got = append(got, f.Location.FilePath+":"+f.Metadata["package"])
		}
	}
	if len(got) != 1 || got[0] != "app/safe.py:flaskk_utils" {
		t.Fatalf("SLOP-001 = %q, want only app/safe.py:flaskk_utils", got)
	}
}
