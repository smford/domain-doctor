package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/smford/domain-doctor/internal/engine"
)

func (m *Model) View() string {
	if m.Report == nil {
		return "Loading domain diagnostics...\n"
	}

	header := headerStyle.Width(m.Width - 2).Render(
		fmt.Sprintf("DOMAIN DOCTOR  •  %s  •  Last Scanned: %s",
			m.Domain, m.Report.Timestamp.Format("15:04:05 MST")),
	)

	// Left Nav Pane (25% width)
	navWidth := (m.Width * 25) / 100
	if navWidth < 20 {
		navWidth = 20
	}
	detailsWidth := m.Width - navWidth - 6
	if detailsWidth < 40 {
		detailsWidth = 40
	}

	paneHeight := m.Height - 6
	if paneHeight < 10 {
		paneHeight = 10
	}

	var navContent strings.Builder
	for i, cat := range m.Categories {
		badge := m.getCategoryBadge(cat)
		label := fmt.Sprintf("%s %s", badge, cat)
		if i == m.SelectedCatIdx {
			navContent.WriteString(activeItemStyle.Width(navWidth - 4).Render("▶ " + label))
		} else {
			navContent.WriteString(inactiveItemStyle.Width(navWidth - 4).Render("  " + label))
		}
		navContent.WriteString("\n")
	}

	navPane := navPaneStyle.
		Width(navWidth).
		Height(paneHeight).
		Render(navContent.String())

	// Right Details Pane
	detailsContent := m.renderDetails(detailsWidth)
	detailsPane := detailsPaneStyle.
		Width(detailsWidth).
		Height(paneHeight).
		Render(detailsContent)

	mainContent := lipgloss.JoinHorizontal(lipgloss.Top, navPane, detailsPane)

	footer := footerStyle.Render(
		"Tab: Switch Pane  •  j/k: Navigate  •  r: Rescan  •  q: Quit",
	)

	return lipgloss.JoinVertical(lipgloss.Left, header, mainContent, footer)
}

func (m *Model) getCategoryBadge(category string) string {
	if category == "Overview" {
		return "●"
	}
	hasCrit := false
	hasWarn := false
	count := 0

	for _, f := range m.Report.Findings {
		if f.Category == category {
			count++
			if f.Severity == engine.SeverityCritical {
				hasCrit = true
			}
			if f.Severity == engine.SeverityWarning {
				hasWarn = true
			}
		}
	}

	if count == 0 {
		return "○"
	}
	if hasCrit {
		return critBadgeStyle.Render("✖")
	}
	if hasWarn {
		return warnBadgeStyle.Render("▲")
	}
	return passBadgeStyle.Render("✔")
}

func (m *Model) renderDetails(width int) string {
	activeCat := m.Categories[m.SelectedCatIdx]
	var b strings.Builder

	if activeCat == "Overview" {
		b.WriteString(fmt.Sprintf("Domain          : %s\n", m.Report.Domain))
		b.WriteString(fmt.Sprintf("Scan Duration   : %s\n", m.Report.Duration))
		b.WriteString(fmt.Sprintf("Nameservers     : %s\n\n", strings.Join(m.Report.Nameservers, ", ")))

		pass, info, warn, crit := 0, 0, 0, 0
		for _, f := range m.Report.Findings {
			switch f.Severity {
			case engine.SeverityPass:
				pass++
			case engine.SeverityInfo:
				info++
			case engine.SeverityWarning:
				warn++
			case engine.SeverityCritical:
				crit++
			}
		}

		b.WriteString(fmt.Sprintf("Audit Findings  : %s %s %s %s\n\n",
			passBadgeStyle.Render(fmt.Sprintf("%d PASS", pass)),
			infoBadgeStyle.Render(fmt.Sprintf("%d INFO", info)),
			warnBadgeStyle.Render(fmt.Sprintf("%d WARN", warn)),
			critBadgeStyle.Render(fmt.Sprintf("%d CRIT", crit)),
		))

		if len(m.Report.NegativeCaches) > 0 {
			b.WriteString(warnBadgeStyle.Render("RFC 2308 Negative Caching Alerts Detected:\n"))
			for _, nc := range m.Report.NegativeCaches {
				b.WriteString(fmt.Sprintf(" • %s on %s (%d sec TTL remaining)\n", nc.CachedState, nc.Resolver, nc.RemainingTTL))
			}
		}
		return b.String()
	}

	// Filter findings for the active category
	filtered := make([]engine.Finding, 0)
	for _, f := range m.Report.Findings {
		if f.Category == activeCat {
			filtered = append(filtered, f)
		}
	}

	if len(filtered) == 0 {
		return fmt.Sprintf("No checks recorded in category: %s\n", activeCat)
	}

	for i, f := range filtered {
		prefix := "  "
		if i == m.SelectedFinding {
			prefix = "▶ "
		}

		badge := passBadgeStyle.Render("[PASS]")
		switch f.Severity {
		case engine.SeverityCritical:
			badge = critBadgeStyle.Render("[CRIT]")
		case engine.SeverityWarning:
			badge = warnBadgeStyle.Render("[WARN]")
		case engine.SeverityInfo:
			badge = infoBadgeStyle.Render("[INFO]")
		}

		b.WriteString(fmt.Sprintf("%s%s %s: %s\n", prefix, badge, f.ID, f.Summary))
		if f.Detail != "" {
			b.WriteString(fmt.Sprintf("     %s\n", f.Detail))
		}
		if f.Remediation != nil {
			b.WriteString(fmt.Sprintf("     Fix: %s\n", f.Remediation.Title))
			if f.Remediation.Suggested != "" {
				b.WriteString(fmt.Sprintf("     Suggested: %s\n", f.Remediation.Suggested))
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}
