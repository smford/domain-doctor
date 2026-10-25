package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/smford/domain-doctor/internal/checks"
	"github.com/smford/domain-doctor/internal/config"
	"github.com/smford/domain-doctor/internal/engine"
	"github.com/smford/domain-doctor/internal/ui/cli"
)

var (
	lintPolicy string
	lintFormat string
	lintOutput string
)

var lintCmd = &cobra.Command{
	Use:   "lint <domain>",
	Short: "Headless CI/CD policy linting",
	Long:  "Evaluates domain security posture and exits with 0 (clean), 1 (critical), or 2 (warnings).",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]

		cfg, err := config.Load(configFile)
		if err != nil {
			return fmt.Errorf("configuration error: %w", err)
		}

		timeout := cfg.ParseTimeout(globalTimeout)
		resolver := customResolver
		if resolver == "" && cfg.Settings.Resolver != "" {
			resolver = cfg.Settings.Resolver
		}

		eng := engine.NewEngine(timeout, 10)
		eng.SetRuleFilter(cfg.IsRuleEnabled)
		eng.SetSeverityOverrides(cfg.Rules.SeverityOverrides)
		checks.RegisterAll(eng)

		report, err := eng.Run(context.Background(), domain, resolver)
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

		var outputContent string

		switch strings.ToLower(lintFormat) {
		case "sarif":
			sarifJSON, err := cli.GenerateSARIF(report, version)
			if err != nil {
				return err
			}
			outputContent = sarifJSON

		case "github-markdown":
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("### Domain Doctor CI Lint Report for `%s`\n\n", domain))
			sb.WriteString(fmt.Sprintf("- **Critical Findings**: %d\n", critCount))
			sb.WriteString(fmt.Sprintf("- **Warnings**: %d\n\n", warnCount))
			for _, f := range report.Findings {
				if f.Severity == engine.SeverityCritical || f.Severity == engine.SeverityWarning {
					ruleRef := f.RuleID
					if ruleRef == "" {
						ruleRef = f.ID
					}
					sb.WriteString(fmt.Sprintf("- **[%s] %s**: %s\n", f.Severity, ruleRef, f.Summary))
				}
			}
			outputContent = sb.String()

		default:
			cli.PrintReport(report)
		}

		if outputContent != "" {
			if lintOutput != "" {
				if err := os.WriteFile(lintOutput, []byte(outputContent), 0644); err != nil {
					return fmt.Errorf("failed to write output file '%s': %w", lintOutput, err)
				}
			} else {
				fmt.Println(outputContent)
			}
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
	lintCmd.Flags().StringVarP(&lintOutput, "output", "o", "", "write report output to specified file path")
}
