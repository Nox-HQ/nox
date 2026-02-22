package main

import (
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// EvidenceItem represents a piece of compliance evidence for a control.
type EvidenceItem struct {
	ControlID string
	RuleID    string
	File      string
	Line      int32
	Message   string
	Stale     bool
}

// collectEvidence gathers evidence from findings for a framework's controls.
func collectEvidence(fw Framework, controlID string, findings []*pluginv1.Finding) []EvidenceItem {
	ruleToControls := make(map[string][]string)
	for _, ctrl := range fw.Controls {
		if controlID != "" && ctrl.ID != controlID {
			continue
		}
		for _, ruleID := range ctrl.NoxRules {
			ruleToControls[ruleID] = append(ruleToControls[ruleID], ctrl.ID)
		}
	}

	var evidence []EvidenceItem
	for _, f := range findings {
		controlIDs, ok := ruleToControls[f.GetRuleId()]
		if !ok {
			continue
		}

		file := ""
		var line int32
		if f.GetLocation() != nil {
			file = f.GetLocation().GetFilePath()
			line = f.GetLocation().GetStartLine()
		}

		for _, cID := range controlIDs {
			evidence = append(evidence, EvidenceItem{
				ControlID: cID,
				RuleID:    f.GetRuleId(),
				File:      file,
				Line:      line,
				Message:   f.GetMessage(),
				Stale:     false, // Real staleness would check scan timestamps
			})
		}
	}

	return evidence
}
