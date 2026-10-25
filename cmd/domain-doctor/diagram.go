package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/smford/domain-doctor/internal/checks"
	"github.com/smford/domain-doctor/internal/diagram"
	"github.com/smford/domain-doctor/internal/engine"
)

var diagramType string

var diagramCmd = &cobra.Command{
	Use:   "diagram <domain>",
	Short: "Generate Mermaid architecture and flow diagrams",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		eng := engine.NewEngine(globalTimeout, 10)
		checks.RegisterAll(eng)

		report, err := eng.Run(context.Background(), domain, customResolver)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		switch strings.ToLower(diagramType) {
		case "spf":
			fmt.Println(diagram.GenerateSPF(report))
		case "mail":
			fmt.Println(diagram.GenerateMailFlow(report))
		case "delegation":
			fallthrough
		default:
			fmt.Println(diagram.GenerateDelegation(report))
		}

		return nil
	},
}

func init() {
	diagramCmd.Flags().StringVar(&diagramType, "type", "delegation", "diagram type (delegation | spf | mail)")
}
