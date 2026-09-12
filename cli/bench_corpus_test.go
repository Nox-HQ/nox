package main

import "testing"

// branchLikeRefs are names that move. A corpus entry pinned to one produces a
// different scan next week for reasons that have nothing to do with nox.
var branchLikeRefs = map[string]bool{
	"main": true, "master": true, "HEAD": true, "develop": true,
	"trunk": true, "latest": true, "": true,
}

// TestCuratedCorpusIsPinnedToImmutableRefs checks that no corpus entry tracks a
// moving ref.
//
// The list's own comment has always said "Pinned to specific refs so bench
// output is reproducible across runs". Four of its eight entries tracked
// `main`, so half the corpus was whatever those projects had merged that
// morning — and a benchmark that moves under you is worse than no benchmark,
// because a number that changed gets attributed to the change you just made.
//
// This is the check the comment was standing in for.
func TestCuratedCorpusIsPinnedToImmutableRefs(t *testing.T) {
	if len(curatedAutoCorpus) == 0 {
		t.Fatal("the corpus is empty; every assertion below passes vacuously")
	}
	for _, e := range curatedAutoCorpus {
		if branchLikeRefs[e.Ref] {
			t.Errorf("%s is pinned to %q, which moves. Pin a tag or a commit SHA, "+
				"or --autocorpus produces a different corpus every run", e.Repo, e.Ref)
		}
	}
}

// TestCuratedCorpusHasNoDuplicates. Two entries for one repo clone into the
// same destination directory, so the second is silently skipped and the corpus
// is quietly smaller than it reads.
func TestCuratedCorpusHasNoDuplicates(t *testing.T) {
	seen := map[string]string{}
	for _, e := range curatedAutoCorpus {
		if prev, dup := seen[e.Repo]; dup {
			t.Errorf("%s appears twice (%q and %q); the clone destination collides "+
				"and one of them is dropped without a word", e.Repo, prev, e.Ref)
		}
		seen[e.Repo] = e.Ref
	}
}

// TestCuratedCorpusEntriesAreWellFormed. A slug without an owner is skipped by
// materialiseAutoCorpus with no message, which is a corpus entry that silently
// is not one.
func TestCuratedCorpusEntriesAreWellFormed(t *testing.T) {
	for _, e := range curatedAutoCorpus {
		if owner, repo := splitRepoSlug(e.Repo); owner == "" || repo == "" {
			t.Errorf("%q is not owner/repo; materialiseAutoCorpus skips it in silence", e.Repo)
		}
	}
}
