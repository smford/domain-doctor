package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/smford/domain-doctor/internal/checks"
	"github.com/smford/domain-doctor/internal/config"
	"github.com/smford/domain-doctor/internal/diagram"
	"github.com/smford/domain-doctor/internal/engine"
	"github.com/smford/domain-doctor/internal/ui/cli"
	"github.com/smford/domain-doctor/internal/ui/tui"
)

var (
	scanJSON     bool
	scanTUI      bool
	scanMermaid  bool
	scanSARIF    bool
	scanFormat   string
	scanOutput   string
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
	scanCmd.Flags().BoolVar(&scanSARIF, "sarif", false, "output findings in SARIF v2.1.0 format")
	scanCmd.Flags().StringVar(&scanFormat, "format", "cli", "output format (cli | json | sarif | markdown | github-markdown)")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "write report output to specified file path")
	scanCmd.Flags().StringVarP(&scanCategory, "category", "c", "", "filter findings to comma-separated categories (e.g. dns,mail)")
	scanCmd.Flags().StringVarP(&scanSeverity, "severity", "s", "", "minimum severity threshold to display (info, warn, crit)")
	scanCmd.Flags().BoolVarP(&scanQuiet, "quiet", "q", false, "quiet mode; suppress banner and show only warnings/criticals")
}

func runScan(ctx context.Context, domain string, asJSON, asTUI, asMermaid bool) error {
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	timeout := cfg.ParseTimeout(globalTimeout)
	resolver := customResolver
	if resolver == "" && cfg.Settings.Resolver != "" {
		resolver = cfg.Settings.Resolver
	}

	eng := engine.NewEngine(timeout, 12)
	eng.SetRuleFilter(cfg.IsRuleEnabled)
	eng.SetSeverityOverrides(cfg.Rules.SeverityOverrides)
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

	if scanSARIF || strings.ToLower(scanFormat) == "sarif" {
		sarifJSON, err := cli.GenerateSARIF(report, version)
		if err != nil {
			return err
		}
		if scanOutput != "" {
			return os.WriteFile(scanOutput, []byte(sarifJSON), 0644)
		}
		fmt.Println(sarifJSON)
		return nil
	}

	if strings.ToLower(scanFormat) == "markdown" || strings.ToLower(scanFormat) == "github-markdown" {
		md := cli.FormatMarkdownReport(report)
		if scanOutput != "" {
			return os.WriteFile(scanOutput, []byte(md), 0644)
		}
		fmt.Println(md)
		return nil
	}

	if asJSON || strings.ToLower(scanFormat) == "json" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		if scanOutput != "" {
			return os.WriteFile(scanOutput, data, 0644)
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
