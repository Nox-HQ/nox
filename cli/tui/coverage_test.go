package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/detail"
	"github.com/nox-hq/nox/core/findings"
)

// testStoreAllSeverities returns a store with findings at every severity level.
func testStoreAllSeverities() *detail.Store {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		ID: "SEC-001:config.env:5", RuleID: "SEC-001",
		Severity:   findings.SeverityHigh,
		Confidence: findings.ConfidenceHigh,
		Location:   findings.Location{FilePath: "config.env", StartLine: 5},
		Message:    "AWS Access Key ID detected",
		Metadata:   map[string]string{"type": "aws_key", "source": "env"},
	})
	fs.Add(findings.Finding{
		ID: "AI-004:mcp.json:10", RuleID: "AI-004",
		Severity:   findings.SeverityCritical,
		Confidence: findings.ConfidenceHigh,
		Location:   findings.Location{FilePath: "mcp.json", StartLine: 10},
		Message:    "MCP write tool exposed",
	})
	fs.Add(findings.Finding{
		ID: "IAC-007:deploy.yaml:42", RuleID: "IAC-007",
		Severity:   findings.SeverityCritical,
		Confidence: findings.ConfidenceMedium,
		Location:   findings.Location{FilePath: "deploy.yaml", StartLine: 42},
		Message:    "Kubernetes pod running as privileged",
	})
	fs.Add(findings.Finding{
		ID: "SEC-002:app.py:1", RuleID: "SEC-002",
		Severity: findings.SeverityMedium,
		Location: findings.Location{FilePath: "app.py", StartLine: 1},
		Message:  "Hardcoded password found",
	})
	fs.Add(findings.Finding{
		ID: "SEC-003:readme.md:1", RuleID: "SEC-003",
		Severity: findings.SeverityLow,
		Location: findings.Location{FilePath: "readme.md", StartLine: 1},
		Message:  "Internal URL detected",
	})
	fs.Add(findings.Finding{
		ID: "SEC-004:notes.txt:0", RuleID: "SEC-004",
		Severity: findings.SeverityInfo,
		Location: findings.Location{FilePath: "notes.txt"},
		Message:  "Informational note about config",
	})
	return detail.LoadFromSet(fs, ".")
}

func testModel() *Model {
	return New(testStoreAllSeverities(), catalog.Catalog(), 3)
}

// --- Init tests ---

func TestInitReturnsNil(t *testing.T) {
	m := testModel()
	cmd := m.Init()
	if cmd != nil {
		t.Error("Init() should return nil")
	}
}

// --- Update with WindowSizeMsg ---

func TestUpdateWindowSizeMsg(t *testing.T) {
	m := testModel()

	result, cmd := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	if cmd != nil {
		t.Error("WindowSizeMsg should return nil cmd")
	}

	model := result.(*Model)
	if model.width != 120 {
		t.Errorf("width = %d, want 120", model.width)
	}
	if model.height != 40 {
		t.Errorf("height = %d, want 40", model.height)
	}
}

func TestUpdateUnknownMsgType(t *testing.T) {
	m := testModel()

	// Passing a string message (not KeyMsg or WindowSizeMsg) should be a no-op.
	result, cmd := m.Update("unknown message type")
	if cmd != nil {
		t.Error("unknown msg type should return nil cmd")
	}
	model := result.(*Model)
	if model.state != listView {
		t.Errorf("state should remain listView, got %d", model.state)
	}
}

// --- handleListKey tests ---

func TestListKeyNavigateUp(t *testing.T) {
	m := testModel()

	// Move down first.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	if m.cursor != 2 {
		t.Fatalf("cursor after two j = %d, want 2", m.cursor)
	}

	// Move up with 'k'.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	if m.cursor != 1 {
		t.Errorf("cursor after k = %d, want 1", m.cursor)
	}
}

func TestListKeyNavigateUpArrow(t *testing.T) {
	m := testModel()

	// Move down, then up with arrow key.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	m.Update(tea.KeyMsg{Type: tea.KeyUp})
	if m.cursor != 0 {
		t.Errorf("cursor after up arrow = %d, want 0", m.cursor)
	}
}

func TestListKeyNavigateUpAtTop(t *testing.T) {
	m := testModel()

	// Cursor is at 0, pressing up should not go negative.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	if m.cursor != 0 {
		t.Errorf("cursor after k at top = %d, want 0", m.cursor)
	}
}

func TestListKeyNavigateDownAtBottom(t *testing.T) {
	m := testModel()

	// Navigate to the last item.
	total := len(m.filtered)
	for i := 0; i < total+2; i++ {
		m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	}
	if m.cursor != total-1 {
		t.Errorf("cursor after many j = %d, want %d", m.cursor, total-1)
	}
}

func TestListKeyDownArrow(t *testing.T) {
	m := testModel()

	m.Update(tea.KeyMsg{Type: tea.KeyDown})
	if m.cursor != 1 {
		t.Errorf("cursor after down arrow = %d, want 1", m.cursor)
	}
}

func TestListKeyQuit(t *testing.T) {
	m := testModel()

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Error("q should return a quit command")
	}
}

func TestListKeyCtrlCQuit(t *testing.T) {
	m := testModel()

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Error("ctrl+c should return a quit command")
	}
}

func TestListKeyEnterWithEmptyFiltered(t *testing.T) {
	// Create a model and filter to nothing.
	m := testModel()

	// Filter to a severity with no findings (cycle through to get to a gap).
	// Set search to something that matches nothing.
	m.filter.search = "nonexistent_finding_xyz"
	m.applyFilter()
	if len(m.filtered) != 0 {
		t.Fatalf("expected 0 filtered results, got %d", len(m.filtered))
	}

	// Enter on empty list should not switch to detail view.
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.state != listView {
		t.Error("enter on empty list should stay in listView")
	}
}

func TestListKeySearch(t *testing.T) {
	m := testModel()

	// Press '/' to enter search mode.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	if !m.filter.searching {
		t.Error("expected searching = true after /")
	}
}

// --- handleDetailKey tests ---

func TestDetailKeyQuit(t *testing.T) {
	m := testModel()

	// Enter detail view.
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.state != detailView {
		t.Fatal("expected detailView after enter")
	}

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Error("q in detail view should return quit command")
	}
}

func TestDetailKeyBack(t *testing.T) {
	m := testModel()

	// Enter detail view.
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.state != detailView {
		t.Fatal("expected detailView")
	}

	// Press esc to go back.
	m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if m.state != listView {
		t.Errorf("state after esc = %d, want listView", m.state)
	}
}

func TestDetailKeyNextItem(t *testing.T) {
	m := testModel()

	// Enter detail view.
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.state != detailView {
		t.Fatal("expected detailView")
	}

	initialCursor := m.cursor

	// Press 'n' to go to next finding.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if m.cursor != initialCursor+1 {
		t.Errorf("cursor after n = %d, want %d", m.cursor, initialCursor+1)
	}
}

func TestDetailKeyPrevItem(t *testing.T) {
	m := testModel()

	// Move cursor down in list view first.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})

	// Enter detail view.
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.state != detailView {
		t.Fatal("expected detailView")
	}

	cursorBefore := m.cursor
	// Press 'p' to go to previous finding.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	if m.cursor != cursorBefore-1 {
		t.Errorf("cursor after p = %d, want %d", m.cursor, cursorBefore-1)
	}
}

func TestDetailKeyPrevItemAtFirst(t *testing.T) {
	m := testModel()

	// Enter detail view at cursor 0.
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.state != detailView {
		t.Fatal("expected detailView")
	}

	// Press 'p' at first item should stay at 0.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	if m.cursor != 0 {
		t.Errorf("cursor after p at first = %d, want 0", m.cursor)
	}
}

func TestDetailKeyNextItemAtLast(t *testing.T) {
	m := testModel()

	// Move to last item.
	total := len(m.filtered)
	for i := 0; i < total-1; i++ {
		m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	}

	// Enter detail view.
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.state != detailView {
		t.Fatal("expected detailView")
	}

	// Press 'n' at last item should stay at last.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if m.cursor != total-1 {
		t.Errorf("cursor after n at last = %d, want %d", m.cursor, total-1)
	}
}

// --- handleSearchKey tests ---

func TestSearchKeyBackspace(t *testing.T) {
	m := testModel()

	// Enter search mode and type some characters.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}})

	if m.filter.search != "ab" {
		t.Fatalf("search = %q, want 'ab'", m.filter.search)
	}

	// Backspace to delete last char.
	m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	if m.filter.search != "a" {
		t.Errorf("search after backspace = %q, want 'a'", m.filter.search)
	}
}

func TestSearchKeyBackspaceOnEmpty(t *testing.T) {
	m := testModel()

	// Enter search mode with empty search string.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	if m.filter.search != "" {
		t.Fatalf("search should be empty initially, got %q", m.filter.search)
	}

	// Backspace on empty should be no-op.
	m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	if m.filter.search != "" {
		t.Errorf("search after backspace on empty = %q, want empty", m.filter.search)
	}
}

func TestSearchKeyEscape(t *testing.T) {
	m := testModel()

	// Enter search mode and type something.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})

	// Escape should end searching.
	m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if m.filter.searching {
		t.Error("expected searching = false after esc")
	}
}

func TestSearchKeyMultiCharIgnored(t *testing.T) {
	m := testModel()

	// Enter search mode.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})

	// Send a multi-rune key message (shouldn't add anything since msg.String()
	// returns a multi-char string).
	searchBefore := m.filter.search

	// Simulate a key that has a multi-character String() representation.
	// The tea.KeyUp type produces "up" string which is > 1 char.
	m.Update(tea.KeyMsg{Type: tea.KeyUp})
	if m.filter.search != searchBefore {
		t.Errorf("search changed after multi-char key: %q", m.filter.search)
	}
}

// --- applyFilter tests ---

func TestApplyFilterCursorClamping(t *testing.T) {
	m := testModel()
	total := len(m.filtered)

	// Move cursor to last position.
	for i := 0; i < total-1; i++ {
		m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	}
	if m.cursor != total-1 {
		t.Fatalf("cursor = %d, want %d", m.cursor, total-1)
	}

	// Apply a filter that reduces the list significantly.
	m.filter.search = "mcp"
	m.applyFilter()

	// Cursor should be clamped.
	if m.cursor >= len(m.filtered) {
		t.Errorf("cursor %d >= filtered count %d after filter", m.cursor, len(m.filtered))
	}
}

func TestApplyFilterEmptyResults(t *testing.T) {
	m := testModel()

	m.filter.search = "nonexistent_string_12345"
	m.applyFilter()

	if len(m.filtered) != 0 {
		t.Errorf("filtered = %d, want 0", len(m.filtered))
	}
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want 0 for empty results", m.cursor)
	}
}

func TestApplyFilterSeverityAndSearch(t *testing.T) {
	m := testModel()

	// Set severity to critical.
	m.filter.cycleSeverity() // -> critical
	m.filter.search = "deploy"
	m.applyFilter()

	// Should find only IAC-007 in deploy.yaml (critical + matches "deploy").
	if len(m.filtered) != 1 {
		t.Errorf("filtered = %d, want 1 (critical + deploy)", len(m.filtered))
	}
	if len(m.filtered) > 0 && m.filtered[0].RuleID != "IAC-007" {
		t.Errorf("filtered[0].RuleID = %q, want IAC-007", m.filtered[0].RuleID)
	}
}

// --- cycleSeverity tests ---

func TestCycleSeverityFullCycle(t *testing.T) {
	f := newFilterState()
	if f.activeSeverity() != "all" {
		t.Errorf("initial severity = %q, want 'all'", f.activeSeverity())
	}

	expectedOrder := []string{"critical", "high", "medium", "low", "info", "all"}
	for _, expected := range expectedOrder {
		f.cycleSeverity()
		got := f.activeSeverity()
		if got != expected {
			t.Errorf("cycleSeverity: got %q, want %q", got, expected)
		}
	}

	// Verify it wraps around again.
	f.cycleSeverity()
	if f.activeSeverity() != "critical" {
		t.Errorf("after full cycle + 1: severity = %q, want 'critical'", f.activeSeverity())
	}
}

// --- severityStyle tests ---

func TestSeverityStyleAllLevels(t *testing.T) {
	tests := []struct {
		severity findings.Severity
	}{
		{findings.SeverityCritical},
		{findings.SeverityHigh},
		{findings.SeverityMedium},
		{findings.SeverityLow},
		{findings.SeverityInfo},
		{findings.Severity("unknown")},
	}
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			style := severityStyle(tt.severity)
			// Verify it returns a non-empty rendered string.
			rendered := style.Render("TEST")
			if rendered == "" {
				t.Errorf("severityStyle(%q).Render() returned empty", tt.severity)
			}
		})
	}
}

// --- severityBadge tests ---

func TestSeverityBadgeAllLevels(t *testing.T) {
	tests := []struct {
		severity findings.Severity
		contains string
	}{
		{findings.SeverityCritical, "CRIT"},
		{findings.SeverityHigh, "HIGH"},
		{findings.SeverityMedium, "MED"},
		{findings.SeverityLow, "LOW"},
		{findings.SeverityInfo, "INFO"},
		{findings.Severity("unknown"), "INFO"},
	}
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			badge := severityBadge(tt.severity)
			if !strings.Contains(badge, tt.contains) {
				t.Errorf("severityBadge(%q) = %q, want to contain %q", tt.severity, badge, tt.contains)
			}
		})
	}
}

// --- wrapText tests ---

func TestWrapTextBasic(t *testing.T) {
	text := "hello world foo bar"
	result := wrapText(text, 20, "  ")
	if result == "" {
		t.Error("wrapText returned empty string")
	}
	// Should start with indent.
	if !strings.HasPrefix(result, "  ") {
		t.Errorf("wrapText should start with indent, got %q", result)
	}
	// Should end with newline.
	if !strings.HasSuffix(result, "\n") {
		t.Errorf("wrapText should end with newline, got %q", result)
	}
}

func TestWrapTextWrapsLongLine(t *testing.T) {
	text := "this is a fairly long sentence that should get wrapped at the specified width boundary"
	result := wrapText(text, 30, "  ")

	// Should contain multiple lines.
	lines := strings.Split(strings.TrimSuffix(result, "\n"), "\n")
	if len(lines) < 2 {
		t.Errorf("expected multiple lines for wrapping, got %d lines: %q", len(lines), result)
	}

	// Each line should not exceed width (accounting for some word boundary flex).
	for _, line := range lines {
		if len(line) > 40 { // Allow some slack for single long words.
			t.Errorf("line too long (%d chars): %q", len(line), line)
		}
	}
}

func TestWrapTextEmptyString(t *testing.T) {
	result := wrapText("", 40, "  ")
	if result != "" {
		t.Errorf("wrapText of empty string = %q, want empty", result)
	}
}

func TestWrapTextZeroWidth(t *testing.T) {
	result := wrapText("hello world", 0, "  ")
	// Width <= 0 should default to 78.
	if result == "" {
		t.Error("wrapText with zero width should still produce output")
	}
}

func TestWrapTextNegativeWidth(t *testing.T) {
	result := wrapText("hello world", -5, "  ")
	if result == "" {
		t.Error("wrapText with negative width should still produce output")
	}
}

func TestWrapTextSingleWord(t *testing.T) {
	result := wrapText("superlongword", 10, "  ")
	if !strings.Contains(result, "superlongword") {
		t.Errorf("wrapText should contain the word, got %q", result)
	}
}

func TestWrapTextNoIndent(t *testing.T) {
	result := wrapText("hello world", 40, "")
	if !strings.HasPrefix(result, "hello") {
		t.Errorf("wrapText with no indent should start with 'hello', got %q", result)
	}
}

// --- renderDetail tests ---

func TestRenderDetailBasic(t *testing.T) {
	m := testModel()

	// Enter detail view.
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.state != detailView {
		t.Fatal("expected detailView")
	}

	view := m.View()
	if view == "" {
		t.Error("detail View() returned empty string")
	}

	// Should contain the finding's rule ID.
	f := m.filtered[m.cursor]
	if !strings.Contains(view, f.RuleID) {
		t.Errorf("detail view should contain rule ID %q", f.RuleID)
	}

	// Should contain the help line.
	if !strings.Contains(view, "esc back") {
		t.Error("detail view should contain help text")
	}
}

func TestRenderDetailWithMetadata(t *testing.T) {
	m := testModel()

	// Find the finding with metadata (SEC-001 has metadata).
	for i, f := range m.filtered {
		if f.RuleID == "SEC-001" {
			m.cursor = i
			break
		}
	}

	m.state = detailView
	view := m.View()

	// Should contain metadata section.
	if !strings.Contains(view, "Metadata") {
		t.Error("detail view should contain 'Metadata' for finding with metadata")
	}
}

func TestRenderDetailNoSelection(t *testing.T) {
	m := testModel()
	m.state = detailView
	m.cursor = -1

	view := m.View()
	if !strings.Contains(view, "No finding selected") {
		t.Errorf("expected 'No finding selected' for invalid cursor, got %q", view)
	}
}

func TestRenderDetailCursorOutOfRange(t *testing.T) {
	m := testModel()
	m.state = detailView
	m.cursor = 999

	view := m.View()
	if !strings.Contains(view, "No finding selected") {
		t.Errorf("expected 'No finding selected' for out-of-range cursor, got %q", view)
	}
}

func TestRenderDetailShowsSeverity(t *testing.T) {
	m := testModel()

	m.state = detailView
	view := m.View()

	// The detail view renders the severity in uppercase.
	sev := strings.ToUpper(string(m.filtered[m.cursor].Severity))
	if !strings.Contains(view, sev) {
		t.Errorf("detail view should contain severity %q", sev)
	}
}

func TestRenderDetailShowsFileLocation(t *testing.T) {
	m := testModel()

	m.state = detailView
	view := m.View()

	f := m.filtered[m.cursor]
	if !strings.Contains(view, f.Location.FilePath) {
		t.Errorf("detail view should contain file path %q", f.Location.FilePath)
	}
}

func TestRenderDetailFileLocationNoStartLine(t *testing.T) {
	// Create a store with a finding that has no start line.
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		ID: "TEST-001:nofile:0", RuleID: "TEST-001",
		Severity: findings.SeverityInfo,
		Location: findings.Location{FilePath: "nofile.txt"},
		Message:  "No line number finding",
	})
	store := detail.LoadFromSet(fs, ".")
	m := New(store, catalog.Catalog(), 3)

	m.state = detailView
	view := m.View()

	// Should show the file path without a line number appended.
	if !strings.Contains(view, "nofile.txt") {
		t.Error("detail view should contain file path without line number")
	}
}

func TestRenderDetailEachFinding(t *testing.T) {
	m := testModel()

	// Verify detail rendering works for every finding in the list.
	for i := range m.filtered {
		m.cursor = i
		m.state = detailView
		view := m.View()
		if view == "" {
			t.Errorf("detail view for finding %d returned empty", i)
		}
		if !strings.Contains(view, m.filtered[i].RuleID) {
			t.Errorf("detail view for finding %d should contain RuleID %q", i, m.filtered[i].RuleID)
		}
	}
}

// --- renderList tests ---

func TestRenderListBasic(t *testing.T) {
	m := testModel()
	view := m.View()

	if !strings.Contains(view, "Nox") {
		t.Error("list view should contain 'Nox'")
	}
	if !strings.Contains(view, "findings") {
		t.Error("list view should contain 'findings'")
	}
	if !strings.Contains(view, "navigate") {
		t.Error("list view should contain help text with 'navigate'")
	}
}

func TestRenderListWithFilter(t *testing.T) {
	m := testModel()

	// Apply severity filter.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	view := m.View()

	// Should show "of X total" since filter is active.
	if !strings.Contains(view, "total") {
		t.Error("list view with filter should show total count")
	}
	// Should show the filter label.
	if !strings.Contains(view, "critical") {
		t.Error("list view should show active severity filter 'critical'")
	}
}

func TestRenderListWithSearch(t *testing.T) {
	m := testModel()

	// Enter search mode.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})

	view := m.View()
	// Should show the search input with cursor.
	if !strings.Contains(view, "Search:") {
		t.Error("list view in search mode should show 'Search:'")
	}
}

func TestRenderListWithCompletedSearch(t *testing.T) {
	m := testModel()

	// Enter search, type, and confirm.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})

	view := m.View()
	// The search term should be shown in the filter line.
	if !strings.Contains(view, "mcp") {
		t.Error("list view after search should show search term 'mcp'")
	}
}

func TestRenderListEmptyFiltered(t *testing.T) {
	m := testModel()

	m.filter.search = "zzz_no_match_ever"
	m.applyFilter()

	view := m.View()
	if !strings.Contains(view, "No findings match") {
		t.Error("list view should show 'No findings match' when no results")
	}
}

func TestRenderListSmallHeight(t *testing.T) {
	m := testModel()
	m.height = 5 // Very small terminal.

	view := m.View()
	if view == "" {
		t.Error("list view should render even with small height")
	}
}

func TestRenderListFilteredCountDiffersFromTotal(t *testing.T) {
	m := testModel()

	// Filter to high severity only.
	m.filter.cycleSeverity() // critical
	m.filter.cycleSeverity() // high
	m.applyFilter()

	view := m.View()
	// When filtered count != total, both should be displayed.
	if !strings.Contains(view, "total") {
		t.Error("should show total count when filtered differs from total")
	}
}

// --- View delegation tests ---

func TestViewListState(t *testing.T) {
	m := testModel()
	m.state = listView

	view := m.View()
	// List view should have the help line with "navigate".
	if !strings.Contains(view, "navigate") {
		t.Error("list view should contain 'navigate' in help")
	}
}

func TestViewDetailState(t *testing.T) {
	m := testModel()
	m.state = detailView
	// Cursor at 0 is valid.

	view := m.View()
	// Detail view should have the help line with "esc back".
	if !strings.Contains(view, "esc back") {
		t.Error("detail view should contain 'esc back' in help")
	}
}

// --- matchesBinding tests ---

func TestMatchesBindingPositive(t *testing.T) {
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}
	if !matchesBinding(msg, keys.Quit) {
		t.Error("q should match Quit binding")
	}
}

func TestMatchesBindingNegative(t *testing.T) {
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}}
	if matchesBinding(msg, keys.Quit) {
		t.Error("x should not match Quit binding")
	}
}

// --- filterState matchesFinding tests ---

func TestMatchesFindingByID(t *testing.T) {
	f := newFilterState()
	f.search = "SEC-001"

	finding := findings.Finding{
		ID:       "SEC-001:config.env:5",
		RuleID:   "SEC-001",
		Severity: findings.SeverityHigh,
		Location: findings.Location{FilePath: "config.env"},
		Message:  "Key detected",
	}

	if !f.matchesFinding(finding) {
		t.Error("search by ID should match")
	}
}

func TestMatchesFindingByMessage(t *testing.T) {
	f := newFilterState()
	f.search = "key detected"

	finding := findings.Finding{
		ID:       "SEC-001:config.env:5",
		RuleID:   "SEC-001",
		Severity: findings.SeverityHigh,
		Location: findings.Location{FilePath: "config.env"},
		Message:  "AWS Access Key Detected in file",
	}

	if !f.matchesFinding(finding) {
		t.Error("case-insensitive search by message should match")
	}
}

func TestMatchesFindingByFilePath(t *testing.T) {
	f := newFilterState()
	f.search = "config"

	finding := findings.Finding{
		ID:       "SEC-001:config.env:5",
		RuleID:   "SEC-001",
		Severity: findings.SeverityHigh,
		Location: findings.Location{FilePath: "config.env"},
		Message:  "Something",
	}

	if !f.matchesFinding(finding) {
		t.Error("search by file path should match")
	}
}

func TestMatchesFindingNoMatch(t *testing.T) {
	f := newFilterState()
	f.search = "zzzzz"

	finding := findings.Finding{
		ID:       "SEC-001:config.env:5",
		RuleID:   "SEC-001",
		Severity: findings.SeverityHigh,
		Location: findings.Location{FilePath: "config.env"},
		Message:  "Something",
	}

	if f.matchesFinding(finding) {
		t.Error("non-matching search should not match")
	}
}

func TestFilterFindingsAll(t *testing.T) {
	f := newFilterState()
	all := []findings.Finding{
		{ID: "1", RuleID: "R1", Severity: findings.SeverityHigh, Message: "a"},
		{ID: "2", RuleID: "R2", Severity: findings.SeverityLow, Message: "b"},
	}
	result := f.filterFindings(all)
	if len(result) != 2 {
		t.Errorf("filterFindings with no filters = %d, want 2", len(result))
	}
}

func TestFilterFindingsBySeverity(t *testing.T) {
	f := newFilterState()
	f.cycleSeverity() // critical

	all := []findings.Finding{
		{ID: "1", Severity: findings.SeverityCritical, Message: "a"},
		{ID: "2", Severity: findings.SeverityHigh, Message: "b"},
		{ID: "3", Severity: findings.SeverityCritical, Message: "c"},
	}
	result := f.filterFindings(all)
	if len(result) != 2 {
		t.Errorf("filterFindings critical = %d, want 2", len(result))
	}
}

// --- renderFindingLine tests ---

func TestRenderFindingLineSelected(t *testing.T) {
	f := findings.Finding{
		RuleID:   "SEC-001",
		Severity: findings.SeverityHigh,
		Location: findings.Location{FilePath: "config.env", StartLine: 5},
		Message:  "AWS Access Key",
	}

	line := renderFindingLine(f, true)
	if !strings.Contains(line, "SEC-001") {
		t.Error("finding line should contain rule ID")
	}
	if !strings.Contains(line, "config.env:5") {
		t.Error("finding line should contain file:line")
	}
}

func TestRenderFindingLineNotSelected(t *testing.T) {
	f := findings.Finding{
		RuleID:   "SEC-001",
		Severity: findings.SeverityHigh,
		Location: findings.Location{FilePath: "config.env", StartLine: 5},
		Message:  "AWS Access Key",
	}

	line := renderFindingLine(f, false)
	if !strings.Contains(line, "SEC-001") {
		t.Error("finding line should contain rule ID")
	}
}

func TestRenderFindingLineNoStartLine(t *testing.T) {
	f := findings.Finding{
		RuleID:   "TEST-001",
		Severity: findings.SeverityInfo,
		Location: findings.Location{FilePath: "somefile.txt"},
		Message:  "Test message",
	}

	line := renderFindingLine(f, false)
	if !strings.Contains(line, "somefile.txt") {
		t.Error("finding line should contain file path")
	}
}

// --- Integration flow tests ---

func TestFullNavigationFlow(t *testing.T) {
	m := testModel()

	// Start in list view.
	if m.state != listView {
		t.Fatal("expected listView")
	}

	// Navigate down twice.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	if m.cursor != 2 {
		t.Fatalf("cursor = %d, want 2", m.cursor)
	}

	// Enter detail.
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.state != detailView {
		t.Fatal("expected detailView")
	}

	// Navigate to next in detail.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if m.cursor != 3 {
		t.Errorf("cursor after n = %d, want 3", m.cursor)
	}

	// Navigate to prev in detail.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	if m.cursor != 2 {
		t.Errorf("cursor after p = %d, want 2", m.cursor)
	}

	// Go back to list.
	m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if m.state != listView {
		t.Fatal("expected listView after esc")
	}

	// Apply severity filter.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if m.filter.activeSeverity() != "critical" {
		t.Errorf("severity = %q, want critical", m.filter.activeSeverity())
	}

	// Search.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.filter.searching {
		t.Error("expected searching = false after enter")
	}
}

func TestSearchFilterCombinedWithSeverity(t *testing.T) {
	m := testModel()

	// Filter to high severity.
	m.filter.cycleSeverity() // critical
	m.filter.cycleSeverity() // high
	m.applyFilter()

	highCount := len(m.filtered)
	if highCount != 1 {
		t.Fatalf("high severity count = %d, want 1", highCount)
	}

	// Now add a search within high severity findings.
	m.filter.search = "AWS"
	m.applyFilter()
	if len(m.filtered) != 1 {
		t.Errorf("high+AWS filtered = %d, want 1", len(m.filtered))
	}

	// Search for something not in high severity.
	m.filter.search = "deploy"
	m.applyFilter()
	if len(m.filtered) != 0 {
		t.Errorf("high+deploy filtered = %d, want 0", len(m.filtered))
	}
}

func TestWindowResizeThenView(t *testing.T) {
	m := testModel()

	m.Update(tea.WindowSizeMsg{Width: 200, Height: 50})

	// Both list and detail views should still render correctly.
	listView := m.View()
	if listView == "" {
		t.Error("list view after resize should not be empty")
	}

	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	detailView := m.View()
	if detailView == "" {
		t.Error("detail view after resize should not be empty")
	}
}

func TestSeverityFilterCycleMedium(t *testing.T) {
	m := testModel()

	// Cycle to medium.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // critical
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // high
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // medium

	if m.filter.activeSeverity() != "medium" {
		t.Errorf("severity = %q, want medium", m.filter.activeSeverity())
	}
	if len(m.filtered) != 1 {
		t.Errorf("medium filtered = %d, want 1", len(m.filtered))
	}
}

func TestSeverityFilterCycleLow(t *testing.T) {
	m := testModel()

	// Cycle to low.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // critical
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // high
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // medium
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // low

	if m.filter.activeSeverity() != "low" {
		t.Errorf("severity = %q, want low", m.filter.activeSeverity())
	}
	if len(m.filtered) != 1 {
		t.Errorf("low filtered = %d, want 1", len(m.filtered))
	}
}

func TestSeverityFilterCycleInfo(t *testing.T) {
	m := testModel()

	// Cycle to info.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // critical
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // high
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // medium
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // low
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // info

	if m.filter.activeSeverity() != "info" {
		t.Errorf("severity = %q, want info", m.filter.activeSeverity())
	}
	if len(m.filtered) != 1 {
		t.Errorf("info filtered = %d, want 1", len(m.filtered))
	}
}

func TestSeverityFilterCycleBackToAll(t *testing.T) {
	m := testModel()

	// Cycle through all severities back to "all".
	for i := 0; i < 6; i++ {
		m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	}

	if m.filter.activeSeverity() != "all" {
		t.Errorf("severity = %q, want all", m.filter.activeSeverity())
	}
	if len(m.filtered) != 6 {
		t.Errorf("all filtered = %d, want 6", len(m.filtered))
	}
}
