package deps

import (
	"sync"

	"github.com/nox-hq/nox/core/npmtree"
	"github.com/nox-hq/nox/core/pypipin"
)

// npmProjects opens each npm workspace a scan reports on once: a lockfile is
// asked about every vulnerable package in it.
type npmProjects struct {
	mu    sync.Mutex
	byDir map[string]*npmtree.Project
}

func (m *npmProjects) open(dir string) *npmtree.Project {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byDir == nil {
		m.byDir = map[string]*npmtree.Project{}
	}
	p, ok := m.byDir[dir]
	if !ok {
		p = npmtree.Open(dir)
		m.byDir[dir] = p
	}
	return p
}

// addNPMRemediation writes the answer nox fix plan and apply give for this
// package (core/npmtree) into a finding's metadata.
//
// A package the project does not list must not be offered `npm install
// pkg@fixed`: that adds a second, direct copy and leaves the one its parent
// loads vulnerable, so the lockfile looks fixed while the finding stays. It is
// offered what apply runs (`npm update pkg`), or, when a parent's range holds
// it, no command and a note naming the parent and the overrides entry.
func addNPMRemediation(meta map[string]string, adv npmtree.Advice, pkg, fixed string) {
	if adv.Command == "" {
		delete(meta, "remediation_command")
	} else {
		meta["remediation_command"] = adv.Command
	}
	if !adv.Transitive {
		return
	}
	meta["remediation_scope"] = "transitive"
	if adv.Reach.Held() {
		meta["remediation_note"] = pkg + " is not listed in package.json, and " + adv.Reach.HoldList() +
			": the range excludes " + fixed + ". Upgrade " + adv.Reach.Holders() +
			" to a release that allows it, or add to package.json: " +
			npmtree.OverrideEntry(adv.Reach.Tool, pkg, fixed)
	}
}

// addPyPIRemediation writes the answer nox fix plan and apply give for a
// Python package (core/pypipin): the pin edit in the finding's own file, or no
// command and why, with the resolver's own command.
func addPyPIRemediation(meta map[string]string, adv pypipin.Advice) {
	if adv.Command != "" {
		meta["remediation_command"] = adv.Command
		return
	}
	delete(meta, "remediation_command")
	meta["remediation_action"] = "manual"
	meta["remediation_note"] = adv.Manual
}
