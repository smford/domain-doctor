package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/smford/domain-doctor/internal/checks"
	"github.com/smford/domain-doctor/internal/engine"
	"github.com/smford/domain-doctor/internal/iac"
)

var exportFormat string

var exportCmd = &cobra.Command{
	Use:   "export <domain>",
	Short: "Export discovered DNS records to BIND zone file or Terraform HCL",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		eng := engine.NewEngine(globalTimeout, 10)
		checks.RegisterAll(eng)

		report, err := eng.Run(context.Background(), domain, customResolver)
		if err != nil {
			return fmt.Errorf("export scan failed: %w", err)
		}

		switch strings.ToLower(exportFormat) {
		case "hcl", "terraform":
			fmt.Println(iac.ExportTerraformRoute53(report))
		case "bind":
			fallthrough
		default:
			fmt.Println(iac.ExportBIND(report))
		}

		return nil
	},
}

func init() {
	exportCmd.Flags().StringVar(&exportFormat, "format", "bind", "export format (bind | hcl)")
}
