package main

import (
	"context"
	"encoding/json"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/smford/domain-doctor/internal/checks"
	"github.com/smford/domain-doctor/internal/diagram"
	"github.com/smford/domain-doctor/internal/engine"
	"github.com/smford/domain-doctor/internal/ui/cli"
	"github.com/smford/domain-doctor/internal/ui/tui"
)

var (
	scanJSON    bool
	scanTUI     bool
	scanMermaid bool
)

var scanCmd = &cobra.Command{
	Use:   "scan <domain>",
	Short: "Execute full diagnostic domain audit",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan(cmd.Context(), args[0], scanJSON, scanTUI, scanMermaid)
	},
}

func init() {
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "output results in raw JSON format")
	scanCmd.Flags().BoolVar(&scanTUI, "tui", false, "launch interactive terminal UI")
	scanCmd.Flags().BoolVar(&scanMermaid, "mermaid", false, "output Mermaid delegation diagram")
}

func runScan(ctx context.Context, domain string, asJSON, asTUI, asMermaid bool) error {
	eng := engine.NewEngine(globalTimeout, 12)
	checks.RegisterAll(eng)

	if asTUI {
		p := tea.NewProgram(tui.NewModel(domain, eng, nil, false, 0), tea.WithAltScreen())
		// Trigger initial scan in background
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

	cli.PrintReport(report)
	return nil
}
