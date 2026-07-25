package mcpdrift

import (
	"encoding/json"
	"sort"
)

// ChangeType classifies how a tool present in both manifests changed.
type ChangeType string

// Change type constants.
const (
	// DescriptionChanged: the tool's advertised description was mutated — the
	// classic rug-pull vector (a benign description swapped for an injected one).
	DescriptionChanged ChangeType = "description_changed"
	// SchemaWidened: the tool's input schema gained one or more properties — a
	// credential-harvesting or capability-expanding change.
	SchemaWidened ChangeType = "schema_widened"
	// SchemaChanged: the tool's input schema changed without adding properties
	// (narrowed, retyped, or reworded).
	SchemaChanged ChangeType = "schema_changed"
)

// ToolChange records one mutation to a tool that exists in both manifests.
type ToolChange struct {
	Tool       string     `json:"tool"`
	Type       ChangeType `json:"type"`
	Before     string     `json:"before"`
	After      string     `json:"after"`
	AddedProps []string   `json:"added_props,omitempty"`
}

// Diff is the deterministic result of comparing a baseline manifest (before)
// against a freshly captured one (after). Any non-empty Diff is drift.
type Diff struct {
	AddedTools   []Tool       `json:"added_tools,omitempty"`
	RemovedTools []string     `json:"removed_tools,omitempty"`
	Changes      []ToolChange `json:"changes,omitempty"`
}

// IsDrift reports whether anything changed between the two manifests.
func (d Diff) IsDrift() bool {
	return len(d.AddedTools) > 0 || len(d.RemovedTools) > 0 || len(d.Changes) > 0
}

// DiffManifests compares before (baseline) against after (current capture) and
// reports exactly what changed: tools added, tools removed, descriptions
// mutated, and input schemas widened or otherwise changed. The result is
// deterministic — every list is sorted by tool name — so re-running against an
// unchanged server yields an identical (empty) diff.
func DiffManifests(before, after Manifest) Diff {
	bByName := before.toolByName()
	aByName := after.toolByName()

	var d Diff

	// Added / removed.
	for name, tool := range aByName {
		if _, ok := bByName[name]; !ok {
			d.AddedTools = append(d.AddedTools, tool)
		}
	}
	for name := range bByName {
		if _, ok := aByName[name]; !ok {
			d.RemovedTools = append(d.RemovedTools, name)
		}
	}

	// Changed (present in both).
	for name, bt := range bByName {
		at, ok := aByName[name]
		if !ok {
			continue
		}
		if bt.Description != at.Description {
			d.Changes = append(d.Changes, ToolChange{
				Tool:   name,
				Type:   DescriptionChanged,
				Before: bt.Description,
				After:  at.Description,
			})
		}
		if string(bt.InputSchema) != string(at.InputSchema) {
			added := addedSchemaProps(bt.InputSchema, at.InputSchema)
			ct := ToolChange{
				Tool:   name,
				Type:   SchemaChanged,
				Before: string(bt.InputSchema),
				After:  string(at.InputSchema),
			}
			if len(added) > 0 {
				ct.Type = SchemaWidened
				ct.AddedProps = added
			}
			d.Changes = append(d.Changes, ct)
		}
	}

	sort.Slice(d.AddedTools, func(i, j int) bool { return d.AddedTools[i].Name < d.AddedTools[j].Name })
	sort.Strings(d.RemovedTools)
	sort.Slice(d.Changes, func(i, j int) bool {
		if d.Changes[i].Tool != d.Changes[j].Tool {
			return d.Changes[i].Tool < d.Changes[j].Tool
		}
		return d.Changes[i].Type < d.Changes[j].Type
	})
	return d
}

// addedSchemaProps returns the names of top-level `properties` keys present in
// after but not in before — the signal that a tool's input surface widened
// (e.g. a new `api_key` field appearing on a previously credential-free tool).
// Returns a sorted, deduplicated list; nil when the schemas are unparseable or
// nothing was added.
func addedSchemaProps(before, after json.RawMessage) []string {
	bProps := schemaProps(before)
	aProps := schemaProps(after)
	var added []string
	for name := range aProps {
		if _, ok := bProps[name]; !ok {
			added = append(added, name)
		}
	}
	sort.Strings(added)
	return added
}

// schemaProps extracts the set of top-level property names from a JSON Schema
// object's `properties` map.
func schemaProps(raw json.RawMessage) map[string]struct{} {
	out := map[string]struct{}{}
	if len(raw) == 0 {
		return out
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		return out
	}
	for name := range schema.Properties {
		out[name] = struct{}{}
	}
	return out
}
