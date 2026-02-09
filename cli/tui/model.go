// Package tui provides an interactive terminal UI for exploring Nox scan
// findings using the Bubble Tea framework.
package tui

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/detail"
	"github.com/nox-hq/nox/core/findings"
)

type viewState int

const (
	listView viewState = iota
	detailView
)

// Model is the root Bubble Tea model for the finding inspector TUI.
type Model struct {
	state        viewState
	store        *detail.Store
	catalog      map[string]catalog.RuleMeta
	filter       filterState
	filtered     []findings.Finding
	cursor       int
	width        int
	height       int
	contextLines int
}

// New creates a new TUI Model with the given store and catalog.
func New(store *detail.Store, cat map[string]catalog.RuleMeta, contextLines int) *Model {
	m := &Model{
		state:        listView,
		store:        store,
		catalog:      cat,
		filter:       newFilterState(),
		contextLines: contextLines,
		width:        80,
		height:       24,
	}
	m.applyFilter()
	return m
}

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// View implements tea.Model.
func (m *Model) View() string {
	switch m.state {
	case detailView:
		return renderDetail(m)
	default:
		return renderList(m)
	}
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle search input mode.
	if m.filter.searching {
		return m.handleSearchKey(msg)
	}

	switch m.state {
	case listView:
		return m.handleListKey(msg)
	case detailView:
		return m.handleDetailKey(msg)
	}
	return m, nil
}

func (m *Model) handleListKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case matchesBinding(msg, keys.Quit):
		return m, tea.Quit

	case matchesBinding(msg, keys.Up):
		if m.cursor > 0 {
			m.cursor--
		}

	case matchesBinding(msg, keys.Down):
		if m.cursor < len(m.filtered)-1 {
			m.cursor++
		}

	case matchesBinding(msg, keys.Enter):
		if len(m.filtered) > 0 {
			m.state = detailView
		}

	case matchesBinding(msg, keys.Search):
		m.filter.searching = true

	case matchesBinding(msg, keys.Severity):
		m.filter.cycleSeverity()
		m.applyFilter()
	}
	return m, nil
}

func (m *Model) handleDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case matchesBinding(msg, keys.Quit):
		return m, tea.Quit

	case matchesBinding(msg, keys.Back):
		m.state = listView

	case matchesBinding(msg, keys.NextItem):
		if m.cursor < len(m.filtered)-1 {
			m.cursor++
		}

	case matchesBinding(msg, keys.PrevItem):
		if m.cursor > 0 {
			m.cursor--
		}
	}
	return m, nil
}

func (m *Model) handleSearchKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc":
		m.filter.searching = false
		m.applyFilter()
	case "backspace":
		if len(m.filter.search) > 0 {
			m.filter.search = m.filter.search[:len(m.filter.search)-1]
			m.applyFilter()
		}
	default:
		if len(msg.String()) == 1 {
			m.filter.search += msg.String()
			m.applyFilter()
		}
	}
	return m, nil
}

func (m *Model) applyFilter() {
	m.filtered = m.filter.filterFindings(m.store.All())
	if m.cursor >= len(m.filtered) {
		m.cursor = len(m.filtered) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

// matchesBinding checks if a key message matches a key binding.
func matchesBinding(msg tea.KeyMsg, binding key.Binding) bool {
	for _, k := range binding.Keys() {
		if msg.String() == k {
			return true
		}
	}
	return false
}
