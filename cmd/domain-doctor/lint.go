package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/smford/domain-doctor/internal/checks"
	"github.com/smford/domain-doctor/internal/engine"
	"github.com/smford/domain-doctor/internal/ui/cli"
)

var (
	lintPolicy string
	lintFormat string
)

var lintCmd = &cobra.Command{
	Use:   "lint <domain>",
	Short: "Headless CI/CD policy linting",
	Long:  "Evaluates domain security posture and exits with 0 (clean), 1 (critical), or 2 (warnings).",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		eng := engine.NewEngine(globalTimeout, 10)
		checks.RegisterAll(eng)

		report, err := eng.Run(context.Background(), domain, customResolver)
		if err != nil {
			return fmt.Errorf("lint audit failed: %w", err)
		}

		critCount := 0
		warnCount := 0
		for _, f := range report.Findings {
			if f.Severity == engine.SeverityCritical {
				critCount++
			} else if f.Severity == engine.SeverityWarning {
				warnCount++
			}
		}

		switch strings.ToLower(lintFormat) {
		case "sarif":
			sarifJSON, err := cli.GenerateSARIF(report, version)
			if err != nil {
				return err
			}
			fmt.Println(sarifJSON)

		case "github-markdown":
			fmt.Printf("### Domain Doctor CI Lint Report for `%s`\n\n", domain)
			fmt.Printf("- **Critical Findings**: %d\n", critCount)
			fmt.Printf("- **Warnings**: %d\n\n", warnCount)
			for _, f := range report.Findings {
				if f.Severity == engine.SeverityCritical || f.Severity == engine.SeverityWarning {
					fmt.Printf("- **[%s] %s**: %s\n", f.Severity, f.ID, f.Summary)
				}
			}

		default:
			cli.PrintReport(report)
		}

		if critCount > 0 {
			os.Exit(1)
		}
		if lintPolicy == "strict" && warnCount > 0 {
			os.Exit(2)
		}

		return nil
	},
}

func init() {
	lintCmd.Flags().StringVar(&lintPolicy, "policy", "standard", "lint enforcement policy (standard | strict)")
	lintCmd.Flags().StringVar(&lintFormat, "format", "cli", "output format (cli | sarif | github-markdown)")
}
