package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/smford/domain-doctor/internal/checks"
	"github.com/smford/domain-doctor/internal/engine"
	"github.com/smford/domain-doctor/internal/iac"
)

var tfStateFile string

var auditDriftCmd = &cobra.Command{
	Use:   "audit-drift <domain>",
	Short: "Audit out-of-band DNS drift against Terraform state",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		if tfStateFile == "" {
			return fmt.Errorf("--tf-state path is required")
		}

		eng := engine.NewEngine(globalTimeout, 10)
		checks.RegisterAll(eng)

		report, err := eng.Run(context.Background(), domain, customResolver)
		if err != nil {
			return fmt.Errorf("live scan failed: %w", err)
		}

		findings, err := iac.AuditDrift(tfStateFile, report)
		if err != nil {
			return err
		}

		fmt.Printf("=== Terraform State Drift Audit for %s ===\n", domain)
		if len(findings) == 0 {
			fmt.Println("No matching Route53 or Cloudflare resources found for domain in state file.")
			return nil
		}

		driftCount := 0
		for _, f := range findings {
			statusSymbol := "✔"
			if f.Status != "MATCH" {
				statusSymbol = "✖"
				driftCount++
			}
			fmt.Printf("%s [%s] %s (%s):\n", statusSymbol, f.Status, f.ResourceName, f.RecordType)
			fmt.Printf("    State : %s\n", f.StateRecords)
			fmt.Printf("    Live  : %s\n", f.LiveRecords)
		}

		if driftCount > 0 {
			fmt.Printf("\n⚠ Drift detected: %d out-of-band discrepancy(ies) between Terraform and live DNS.\n", driftCount)
		} else {
			fmt.Println("\n✔ Perfect match: Live DNS records align with declared Terraform state.")
		}

		return nil
	},
}

func init() {
	auditDriftCmd.Flags().StringVar(&tfStateFile, "tf-state", "", "path to terraform.tfstate file")
	_ = auditDriftCmd.MarkFlagRequired("tf-state")
}
