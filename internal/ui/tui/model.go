package tui

import (
	"context"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/smford/domain-doctor/internal/engine"
)

type tickMsg time.Time

type scanCompleteMsg struct {
	report *engine.DiagnosticReport
	err    error
}

type Model struct {
	Domain          string
	CustomResolver  string
	Engine          *engine.Engine
	Report          *engine.DiagnosticReport
	Categories      []string
	SelectedCatIdx  int
	SelectedFinding int
	ActivePane      int // 0 = nav, 1 = details
	WatchMode       bool
	WatchInterval   time.Duration
	Width           int
	Height          int
	Scanning        bool
	Err             error
}

func NewModel(domain string, eng *engine.Engine, initialReport *engine.DiagnosticReport, watchMode bool, interval time.Duration) *Model {
	if interval <= 0 {
		interval = 3 * time.Second
	}
	return &Model{
		Domain:         domain,
		Engine:         eng,
		Report:         initialReport,
		WatchMode:      watchMode,
		WatchInterval:  interval,
		Categories:     []string{"Overview", "DNS", "NegativeCache", "Mail", "Security", "Resilience", "Threat", "Registration"},
		SelectedCatIdx: 0,
		ActivePane:     0,
		Width:          100,
		Height:         30,
	}
}

func (m *Model) Init() tea.Cmd {
	if m.WatchMode {
		return tea.Tick(m.WatchInterval, func(t time.Time) tea.Msg {
			return tickMsg(t)
		})
	}
	return nil
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		return m, nil

	case tickMsg:
		if m.WatchMode && !m.Scanning {
			m.Scanning = true
			return m, m.runScanCmd()
		}
		return m, nil

	case scanCompleteMsg:
		m.Scanning = false
		if msg.err == nil {
			m.Report = msg.report
		} else {
			m.Err = msg.err
		}
		if m.WatchMode {
			return m, tea.Tick(m.WatchInterval, func(t time.Time) tea.Msg {
				return tickMsg(t)
			})
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.ActivePane = (m.ActivePane + 1) % 2
			return m, nil
		case "shift+tab":
			m.ActivePane = (m.ActivePane + 1) % 2
			return m, nil
		case "up", "k":
			if m.ActivePane == 0 {
				if m.SelectedCatIdx > 0 {
					m.SelectedCatIdx--
					m.SelectedFinding = 0
				}
			} else {
				if m.SelectedFinding > 0 {
					m.SelectedFinding--
				}
			}
			return m, nil
		case "down", "j":
			if m.ActivePane == 0 {
				if m.SelectedCatIdx < len(m.Categories)-1 {
					m.SelectedCatIdx++
					m.SelectedFinding = 0
				}
			} else {
				m.SelectedFinding++
			}
			return m, nil
		case "r":
			if !m.Scanning {
				m.Scanning = true
				return m, m.runScanCmd()
			}
		}
	}

	return m, nil
}

func (m *Model) runScanCmd() tea.Cmd {
	return func() tea.Msg {
		rep, err := m.Engine.Run(context.Background(), m.Domain, m.CustomResolver)
		return scanCompleteMsg{report: rep, err: err}
	}
}
