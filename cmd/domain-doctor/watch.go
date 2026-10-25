package main

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/smford/domain-doctor/internal/checks"
	"github.com/smford/domain-doctor/internal/engine"
	"github.com/smford/domain-doctor/internal/ui/tui"
)

var watchInterval time.Duration

var watchCmd = &cobra.Command{
	Use:   "watch <domain>",
	Short: "Live cutover watch mode with continuous polling",
	Long:  "Monitors SOA serial changes, record transitions, and negative cache TTL evictions during cutover.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		eng := engine.NewEngine(globalTimeout, 10)
		checks.RegisterAll(eng)

		initialReport, err := eng.Run(context.Background(), domain, customResolver)
		if err != nil {
			return fmt.Errorf("initial scan failed: %w", err)
		}

		model := tui.NewModel(domain, eng, initialReport, true, watchInterval)
		p := tea.NewProgram(model, tea.WithAltScreen())
		_, runErr := p.Run()
		return runErr
	},
}

func init() {
	watchCmd.Flags().DurationVarP(&watchInterval, "interval", "i", 3*time.Second, "polling interval")
}
