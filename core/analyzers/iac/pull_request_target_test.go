package iac

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// pull_request_target runs a fork's pull request with the base repository's
// secrets and its cache scope. IAC-011 matched only `pull_request_target:` with
// a colon, so the scalar and list forms of `on:` — `on: pull_request_target`,
// `on: [push, pull_request_target]` — were never reported, and they are the
// forms the 2026 prt-scan campaign found in the wild.

const prtSteps = `jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: make
`

func TestIAC011ReadsEveryFormOfTheTrigger(t *testing.T) {
	cases := []struct {
		name     string
		file     string
		fires    bool
		wantLine int
	}{
		{"map form", "name: w\non:\n  pull_request_target:\n    branches: [main]\n" + prtSteps, true, 3},
		{"scalar form", "name: w\non: pull_request_target\n" + prtSteps, true, 2},
		{"list form", "name: w\non: [push, pull_request_target]\n" + prtSteps, true, 2},
		{"quoted on key", "name: w\n\"on\": pull_request_target\n" + prtSteps, true, 2},
		{"sequence form", "name: w\non:\n  - push\n  - pull_request_target\n" + prtSteps, true, 4},
		{"comment only", "name: w\n# do not use pull_request_target here\non: pull_request\n" + prtSteps, false, 0},
		{"event-name check in a pull_request workflow", "name: w\non: pull_request\njobs:\n  b:\n    if: github.event_name != 'pull_request_target'\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n", false, 0},
		{"plain pull_request", "name: w\non: pull_request\n" + prtSteps, false, 0},
	}
	a := NewAnalyzer()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := a.ScanFile(".github/workflows/w.yml", []byte(tc.file))
			if err != nil {
				t.Fatal(err)
			}
			hits := byRule(got, "IAC-011")
			if (len(hits) > 0) != tc.fires {
				t.Fatalf("IAC-011 fired %d times, want fires=%v\n%s", len(hits), tc.fires, tc.file)
			}
			if !tc.fires {
				return
			}
			if len(hits) != 1 {
				t.Errorf("IAC-011 fired %d times, want once per workflow", len(hits))
			}
			if hits[0].Location.StartLine != tc.wantLine {
				t.Errorf("IAC-011 at line %d, want the trigger at line %d", hits[0].Location.StartLine, tc.wantLine)
			}
		})
	}
}

// A workflow that runs on pull_request_target (or on workflow_run, which runs
// privileged after an untrusted workflow) and checks out the pull request's own
// commit executes the fork's code with the base repository's secrets: the
// "pwn request". IAC-505 reports the checkout; IAC-506 reports a cache that
// such a job writes, because the base branch's other workflows — a release —
// restore it.
func TestPwnRequestAndCachePoisoning(t *testing.T) {
	const checkoutHead = `      - uses: actions/checkout@0ad4b8fadaa221de15dcec353f45205ec38ea70b
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`
	const setupNodeCache = `      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
        with:
          cache: pnpm
`
	const actionsCache = `      - uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830
        with:
          path: ~/.pnpm-store
          key: pnpm-${{ hashFiles('pnpm-lock.yaml') }}
`
	const run = "      - run: pnpm install && pnpm test\n"
	wf := func(on string, steps ...string) string {
		s := "name: w\non: " + on + "\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
		for _, st := range steps {
			s += st
		}
		return s
	}
	cases := []struct {
		name      string
		file      string
		pwn, pois bool
	}{
		{"prt checks out the PR head", wf("pull_request_target", checkoutHead, run), true, false},
		{"prt head ref", wf("pull_request_target", "      - uses: actions/checkout@0ad4b8fadaa221de15dcec353f45205ec38ea70b\n        with:\n          ref: ${{ github.head_ref }}\n", run), true, false},
		{"prt head sha with a fallback", wf("pull_request_target", "      - uses: actions/checkout@0ad4b8fadaa221de15dcec353f45205ec38ea70b\n        with:\n          ref: ${{ github.event.pull_request.head.sha || github.sha }}\n", run), true, false},
		{"a ref input of an action that only waits on checks", wf("pull_request_target", "      - uses: lewagon/wait-on-check-action@ccfb013c15c8afb7bf2b7c028fb74dc5a068cccc\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", actionsCache), false, false},
		{"a reusable workflow given the head sha", "name: w\non: pull_request_target\njobs:\n  test:\n    uses: ./.github/workflows/_test.yml\n    with:\n      ref: ${{ github.event.pull_request.head.sha }}\n", true, false},
		{"prt merge ref", wf("pull_request_target", "      - uses: actions/checkout@0ad4b8fadaa221de15dcec353f45205ec38ea70b\n        with:\n          ref: refs/pull/${{ github.event.pull_request.number }}/merge\n", run), true, false},
		{"workflow_run checks out the head sha", wf("workflow_run", "      - uses: actions/checkout@0ad4b8fadaa221de15dcec353f45205ec38ea70b\n        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n", run), true, false},
		{"prt head checkout writes a setup-node cache", wf("pull_request_target", checkoutHead, setupNodeCache, run), true, true},
		{"prt head checkout writes actions/cache", wf("pull_request_target", checkoutHead, actionsCache, run), true, true},
		{"prt on the base commit only", wf("pull_request_target", "      - uses: actions/checkout@0ad4b8fadaa221de15dcec353f45205ec38ea70b\n", setupNodeCache, run), false, false},
		{"pull_request checking out the head is the default and harmless", wf("pull_request", checkoutHead, setupNodeCache, run), false, false},
		{"push", wf("push", checkoutHead, actionsCache, run), false, false},
	}
	a := NewAnalyzer()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := a.ScanFile(".github/workflows/w.yml", []byte(tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if g := len(byRule(got, "IAC-505")) > 0; g != tc.pwn {
				t.Errorf("IAC-505 fired = %v, want %v\n%s", g, tc.pwn, tc.file)
			}
			if g := len(byRule(got, "IAC-506")) > 0; g != tc.pois {
				t.Errorf("IAC-506 fired = %v, want %v\n%s", g, tc.pois, tc.file)
			}
			if n := len(byRule(got, "IAC-505")); n > 1 {
				t.Errorf("IAC-505 fired %d times, want once per workflow", n)
			}
		})
	}
}

// Jobs decide what a workflow-level trigger cannot: securego/gosec's CI runs on
// push, pull_request and pull_request_target, saves caches only in jobs whose
// `if:` keeps them off pull_request_target, and checks out the pull request in
// one privileged job that saves no cache.
func TestPwnRequestIsDecidedPerJob(t *testing.T) {
	const gosecShape = `name: CI
on:
  push:
  pull_request:
  pull_request_target:
jobs:
  test:
    if: github.event_name != 'pull_request_target'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0ad4b8fadaa221de15dcec353f45205ec38ea70b
      - uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830
        with:
          path: ~/go/pkg/mod
          key: go-${{ hashFiles('go.sum') }}
  review:
    if: github.event_name == 'pull_request_target'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0ad4b8fadaa221de15dcec353f45205ec38ea70b
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./review.sh
`
	const headOnlyOnPush = `name: CI
on:
  push:
  pull_request_target:
jobs:
  build:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0ad4b8fadaa221de15dcec353f45205ec38ea70b
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
        with:
          cache: npm
`
	const unreadableCondition = `name: CI
on: pull_request_target
jobs:
  build:
    if: contains(github.event.pull_request.labels.*.name, 'safe to test')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0ad4b8fadaa221de15dcec353f45205ec38ea70b
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
        with:
          cache: npm
`
	cases := []struct {
		name      string
		file      string
		pwn, pois bool
	}{
		{"gosec: caches only in jobs kept off pull_request_target", gosecShape, true, false},
		{"head checkout in a push-only job", headOnlyOnPush, false, false},
		{"a label gate is not an exclusion", unreadableCondition, true, true},
	}
	a := NewAnalyzer()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := a.ScanFile(".github/workflows/ci.yml", []byte(tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if g := len(byRule(got, "IAC-505")) > 0; g != tc.pwn {
				t.Errorf("IAC-505 fired = %v, want %v", g, tc.pwn)
			}
			if g := len(byRule(got, "IAC-506")) > 0; g != tc.pois {
				t.Errorf("IAC-506 fired = %v, want %v", g, tc.pois)
			}
		})
	}
}

func byRule(fs []findings.Finding, id string) []findings.Finding {
	var out []findings.Finding
	for _, f := range fs {
		if f.RuleID == id {
			out = append(out, f)
		}
	}
	return out
}
