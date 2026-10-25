package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/smford/domain-doctor/internal/checks"
	"github.com/smford/domain-doctor/internal/diagram"
	"github.com/smford/domain-doctor/internal/engine"
	"github.com/smford/domain-doctor/internal/ui/cli"
	"github.com/smford/domain-doctor/internal/ui/tui"
)

var (
	scanJSON     bool
	scanTUI      bool
	scanMermaid  bool
	scanCategory string
	scanSeverity string
	scanQuiet    bool
)

var scanCmd = &cobra.Command{
	Use:   "scan <domain>",
	Short: "Execute full diagnostic domain audit",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan(cmd.Context(), sanitizeDomain(args[0]), scanJSON, scanTUI, scanMermaid)
	},
}

func init() {
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "output results in raw JSON format")
	scanCmd.Flags().BoolVar(&scanTUI, "tui", false, "launch interactive terminal UI")
	scanCmd.Flags().BoolVar(&scanMermaid, "mermaid", false, "output Mermaid delegation diagram")
	scanCmd.Flags().StringVarP(&scanCategory, "category", "c", "", "filter findings to comma-separated categories (e.g. dns,mail)")
	scanCmd.Flags().StringVarP(&scanSeverity, "severity", "s", "", "minimum severity threshold to display (info, warn, crit)")
	scanCmd.Flags().BoolVarP(&scanQuiet, "quiet", "q", false, "quiet mode; suppress banner and show only warnings/criticals")
}

func runScan(ctx context.Context, domain string, asJSON, asTUI, asMermaid bool) error {
	eng := engine.NewEngine(globalTimeout, 12)
	checks.RegisterAll(eng)

	if asTUI {
		p := tea.NewProgram(tui.NewModel(domain, eng, nil, false, 0), tea.WithAltScreen())
		go func() {
			rep, err := eng.Run(ctx, domain, customResolver)
			if err == nil {
				p.Send(rep)
			}
		}()
		_, err := p.Run()
		return err
	}

	report, err := eng.Run(ctx, domain, customResolver)
	if err != nil {
		return fmt.Errorf("audit execution failed: %w", err)
	}

	if asJSON {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	if asMermaid {
		fmt.Println(diagram.GenerateDelegation(report))
		return nil
	}

	var catFilter []string
	if scanCategory != "" {
		catFilter = strings.Split(scanCategory, ",")
	}

	minSev := engine.Severity("")
	switch strings.ToLower(scanSeverity) {
	case "info":
		minSev = engine.SeverityInfo
	case "warn", "warning":
		minSev = engine.SeverityWarning
	case "crit", "critical":
		minSev = engine.SeverityCritical
	}

	cli.PrintReportFiltered(report, catFilter, minSev, scanQuiet)
	return nil
}
