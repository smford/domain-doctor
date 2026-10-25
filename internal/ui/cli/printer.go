package cli

import (
	"fmt"
	"strings"

	"github.com/smford/domain-doctor/internal/engine"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31;1m"
	colorGreen  = "\033[32;1m"
	colorYellow = "\033[33;1m"
	colorBlue   = "\033[34;1m"
	colorCyan   = "\033[36;1m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

func ComputeHealthScore(report *engine.DiagnosticReport) (int, string) {
	score := 100
	for _, f := range report.Findings {
		switch f.Severity {
		case engine.SeverityCritical:
			score -= 25
		case engine.SeverityWarning:
			score -= 10
		}
	}
	if score < 0 {
		score = 0
	}

	var grade string
	switch {
	case score >= 95:
		grade = "A+"
	case score >= 90:
		grade = "A"
	case score >= 85:
		grade = "B+"
	case score >= 80:
		grade = "B"
	case score >= 70:
		grade = "C"
	case score >= 60:
		grade = "D"
	default:
		grade = "F"
	}
	return score, grade
}

func severityRank(s engine.Severity) int {
	switch s {
	case engine.SeverityPass:
		return 1
	case engine.SeverityInfo:
		return 2
	case engine.SeverityWarning:
		return 3
	case engine.SeverityCritical:
		return 4
	default:
		return 0
	}
}

func PrintReportFiltered(report *engine.DiagnosticReport, categoryFilter []string, minSeverity engine.Severity, quiet bool) {
	catMap := make(map[string]bool)
	for _, c := range categoryFilter {
		catMap[strings.ToLower(strings.TrimSpace(c))] = true
	}

	minRank := severityRank(minSeverity)

	if !quiet {
		score, grade := ComputeHealthScore(report)
		gradeColor := colorGreen
		if score < 70 {
			gradeColor = colorRed
		} else if score < 85 {
			gradeColor = colorYellow
		}

		fmt.Printf("\n%s╔════════════════════════════════════════════════════════════════════╗%s\n", colorCyan, colorReset)
		fmt.Printf("%s║                    DOMAIN DOCTOR AUDIT REPORT                      ║%s\n", colorCyan, colorReset)
		fmt.Printf("%s╚════════════════════════════════════════════════════════════════════╝%s\n", colorCyan, colorReset)

		fmt.Printf("%sTarget Domain   :%s %s%s%s\n", colorBold, colorReset, colorCyan, report.Domain, colorReset)
		fmt.Printf("%sOverall Health  :%s %s%d/100 (Grade: %s)%s\n", colorBold, colorReset, gradeColor, score, grade, colorReset)
		fmt.Printf("%sScan Duration   :%s %s\n", colorBold, colorReset, report.Duration)
		fmt.Printf("%sNameservers     :%s %s\n", colorBold, colorReset, strings.Join(report.Nameservers, ", "))

		passCount, infoCount, warnCount, critCount := 0, 0, 0, 0
		for _, f := range report.Findings {
			switch f.Severity {
			case engine.SeverityPass:
				passCount++
			case engine.SeverityInfo:
				infoCount++
			case engine.SeverityWarning:
				warnCount++
			case engine.SeverityCritical:
				critCount++
			}
		}

		fmt.Printf("%sFindings Summary :%s %s%d PASS%s | %s%d INFO%s | %s%d WARN%s | %s%d CRIT%s\n\n",
			colorBold, colorReset,
			colorGreen, passCount, colorReset,
			colorBlue, infoCount, colorReset,
			colorYellow, warnCount, colorReset,
			colorRed, critCount, colorReset)
	}

	// Group findings by category
	categories := []string{"DNS", "NegativeCache", "Mail", "Security", "Resilience", "Threat", "Registration"}
	grouped := make(map[string][]engine.Finding)
	for _, f := range report.Findings {
		// Category filter check
		if len(catMap) > 0 && !catMap[strings.ToLower(f.Category)] {
			continue
		}
		// Severity filter check
		if minRank > 0 && severityRank(f.Severity) < minRank {
			continue
		}
		grouped[f.Category] = append(grouped[f.Category], f)
	}

	for _, cat := range categories {
		findings, exists := grouped[cat]
		if !exists || len(findings) == 0 {
			continue
		}

		if !quiet {
			fmt.Printf("%s── %s Checks ────────────────────────────────────────────────────────%s\n", colorBold, strings.ToUpper(cat), colorReset)
		}
		for _, f := range findings {
			badge := formatBadge(f.Severity)
			ruleTag := ""
			if f.RuleID != "" {
				ruleTag = fmt.Sprintf(" (%s)", f.RuleID)
			}
			fmt.Printf("  %s %s%s%s%s: %s\n", badge, colorBold, f.ID, ruleTag, colorReset, f.Summary)
			if f.Detail != "" && !quiet {
				fmt.Printf("    %s%s%s\n", colorGray, f.Detail, colorReset)
			}
		}
		if !quiet {
			fmt.Println()
		}
	}

	// Actionable Remediations section
	remediations := make([]*engine.Remediation, 0)
	for _, f := range report.Findings {
		if f.Remediation != nil {
			if len(catMap) > 0 && !catMap[strings.ToLower(f.Category)] {
				continue
			}
			if minRank > 0 && severityRank(f.Severity) < minRank {
				continue
			}
			remediations = append(remediations, f.Remediation)
		}
	}

	if len(remediations) > 0 {
		fmt.Printf("%s════ Actionable Remediation Summary ═══════════════════════════════════%s\n", colorYellow, colorReset)
		for i, rem := range remediations {
			fmt.Printf("%s%d. %s%s\n", colorBold, i+1, rem.Title, colorReset)
			fmt.Printf("   %s\n", rem.Explanation)
			if rem.Suggested != "" {
				fmt.Printf("   %sSuggested Action / Record:%s\n", colorCyan, colorReset)
				for _, line := range strings.Split(rem.Suggested, "\n") {
					fmt.Printf("     %s%s%s\n", colorGreen, line, colorReset)
				}
			}
			if rem.DocURL != "" {
				fmt.Printf("   %sReference:%s %s\n", colorGray, colorReset, rem.DocURL)
			}
			fmt.Println()
		}
	}
}

func PrintReport(report *engine.DiagnosticReport) {
	PrintReportFiltered(report, nil, "", false)
}

func formatBadge(s engine.Severity) string {
	switch s {
	case engine.SeverityPass:
		return fmt.Sprintf("%s[PASS]%s", colorGreen, colorReset)
	case engine.SeverityInfo:
		return fmt.Sprintf("%s[INFO]%s", colorBlue, colorReset)
	case engine.SeverityWarning:
		return fmt.Sprintf("%s[WARN]%s", colorYellow, colorReset)
	case engine.SeverityCritical:
		return fmt.Sprintf("%s[CRIT]%s", colorRed, colorReset)
	default:
		return "[    ]"
	}
}

// FormatMarkdownReport generates a GitHub Flavored Markdown summary report for Step Summaries and CI/CD logs.
func FormatMarkdownReport(report *engine.DiagnosticReport) string {
	score, grade := ComputeHealthScore(report)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("### 🛡️ Domain Doctor Diagnostic Report: `%s`\n\n", report.Domain))
	sb.WriteString(fmt.Sprintf("* **Health Score**: **%d / 100** (Grade: `%s`)\n", score, grade))
	if len(report.Nameservers) > 0 {
		sb.WriteString(fmt.Sprintf("* **Authoritative Nameservers**: `%s`\n", strings.Join(report.Nameservers, "`, `")))
	}
	sb.WriteString(fmt.Sprintf("* **Audit Timestamp**: %s\n\n", report.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC")))

	critCount, warnCount, infoCount, passCount := 0, 0, 0, 0
	for _, f := range report.Findings {
		switch f.Severity {
		case engine.SeverityCritical:
			critCount++
		case engine.SeverityWarning:
			warnCount++
		case engine.SeverityInfo:
			infoCount++
		case engine.SeverityPass:
			passCount++
		}
	}

	sb.WriteString(fmt.Sprintf("| Status | Count |\n| :--- | :---: |\n| ❌ Critical | %d |\n| ⚠️ Warning | %d |\n| ℹ️ Info | %d |\n| ✅ Pass | %d |\n\n", critCount, warnCount, infoCount, passCount))

	sb.WriteString("| Rule ID | Category | Status | Summary | Details |\n")
	sb.WriteString("| :--- | :--- | :---: | :--- | :--- |\n")
	for _, f := range report.Findings {
		ruleRef := f.RuleID
		if ruleRef == "" {
			ruleRef = f.ID
		}
		var badge string
		switch f.Severity {
		case engine.SeverityCritical:
			badge = "❌ CRIT"
		case engine.SeverityWarning:
			badge = "⚠️ WARN"
		case engine.SeverityInfo:
			badge = "ℹ️ INFO"
		case engine.SeverityPass:
			badge = "✅ PASS"
		default:
			badge = string(f.Severity)
		}
		cleanSummary := strings.ReplaceAll(f.Summary, "|", "\\|")
		cleanDetail := strings.ReplaceAll(f.Detail, "|", "\\|")
		sb.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s | %s |\n", ruleRef, f.Category, badge, cleanSummary, cleanDetail))
	}

	return sb.String()
}
