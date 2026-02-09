package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/detail"
	"github.com/nox-hq/nox/core/findings"
)

func testStore() *detail.Store {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		ID: "SEC-001:config.env:5", RuleID: "SEC-001",
		Severity: findings.SeverityHigh,
		Location: findings.Location{FilePath: "config.env", StartLine: 5},
		Message:  "AWS Access Key ID detected",
	})
	fs.Add(findings.Finding{
		ID: "AI-004:mcp.json:10", RuleID: "AI-004",
		Severity: findings.SeverityCritical,
		Location: findings.Location{FilePath: "mcp.json", StartLine: 10},
		Message:  "MCP write tool exposed",
	})
	fs.Add(findings.Finding{
		ID: "IAC-007:deploy.yaml:42", RuleID: "IAC-007",
		Severity: findings.SeverityCritical,
		Location: findings.Location{FilePath: "deploy.yaml", StartLine: 42},
		Message:  "Kubernetes pod running as privileged",
	})
	return detail.LoadFromSet(fs, ".")
}

func TestNewModel(t *testing.T) {
	store := testStore()
	cat := catalog.Catalog()
	m := New(store, cat, 5)

	if m.state != listView {
		t.Errorf("initial state = %d, want listView (0)", m.state)
	}
	if len(m.filtered) != 3 {
		t.Errorf("filtered count = %d, want 3", len(m.filtered))
	}
}

func TestModelNavigateDown(t *testing.T) {
	store := testStore()
	cat := catalog.Catalog()
	m := New(store, cat, 5)

	if m.cursor != 0 {
		t.Errorf("initial cursor = %d, want 0", m.cursor)
	}

	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	if m.cursor != 1 {
		t.Errorf("cursor after j = %d, want 1", m.cursor)
	}
}

func TestModelEnterDetail(t *testing.T) {
	store := testStore()
	cat := catalog.Catalog()
	m := New(store, cat, 5)

	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.state != detailView {
		t.Errorf("state after enter = %d, want detailView (1)", m.state)
	}

	m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if m.state != listView {
		t.Errorf("state after esc = %d, want listView (0)", m.state)
	}
}

func TestModelSeverityFilter(t *testing.T) {
	store := testStore()
	cat := catalog.Catalog()
	m := New(store, cat, 5)

	// Initially all 3 findings.
	if len(m.filtered) != 3 {
		t.Errorf("initial filtered = %d, want 3", len(m.filtered))
	}

	// Press 's' to cycle to critical.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if m.filter.activeSeverity() != "critical" {
		t.Errorf("after first s: severity = %q, want critical", m.filter.activeSeverity())
	}
	if len(m.filtered) != 2 {
		t.Errorf("critical filtered = %d, want 2", len(m.filtered))
	}

	// Press 's' again to cycle to high.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if m.filter.activeSeverity() != "high" {
		t.Errorf("after second s: severity = %q, want high", m.filter.activeSeverity())
	}
	if len(m.filtered) != 1 {
		t.Errorf("high filtered = %d, want 1", len(m.filtered))
	}
}

func TestModelSearch(t *testing.T) {
	store := testStore()
	cat := catalog.Catalog()
	m := New(store, cat, 5)

	// Enter search mode.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	if !m.filter.searching {
		t.Error("expected searching = true after /")
	}

	// Type "mcp".
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})

	// Confirm search.
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.filter.searching {
		t.Error("expected searching = false after enter")
	}
	if len(m.filtered) != 1 {
		t.Errorf("search filtered = %d, want 1", len(m.filtered))
	}
}

func TestModelView(t *testing.T) {
	store := testStore()
	cat := catalog.Catalog()
	m := New(store, cat, 5)

	// Should render without panic.
	view := m.View()
	if view == "" {
		t.Error("View() returned empty string")
	}
}
