package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/smford/domain-doctor/internal/checks"
	"github.com/smford/domain-doctor/internal/diff"
	"github.com/smford/domain-doctor/internal/engine"
)

var snapshotOutputFile string

var snapshotCmd = &cobra.Command{
	Use:   "snapshot <domain>",
	Short: "Export zone topology and records to a JSON snapshot file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		if snapshotOutputFile == "" {
			snapshotOutputFile = fmt.Sprintf("%s-snapshot.json", domain)
		}

		eng := engine.NewEngine(globalTimeout, 10)
		checks.RegisterAll(eng)

		report, err := eng.Run(context.Background(), domain, customResolver)
		if err != nil {
			return fmt.Errorf("snapshot scan failed: %w", err)
		}

		snap := diff.CreateSnapshot(report)
		if err := diff.SaveSnapshot(snap, snapshotOutputFile); err != nil {
			return fmt.Errorf("failed to save snapshot: %w", err)
		}

		fmt.Printf("✓ Saved snapshot of %s to %s\n", domain, snapshotOutputFile)
		return nil
	},
}

var diffCmd = &cobra.Command{
	Use:   "diff <snapshot.json> <domain>",
	Short: "Compare a JSON snapshot against live DNS topology",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		snapshotFile := args[0]
		domain := args[1]

		snap, err := diff.LoadSnapshot(snapshotFile)
		if err != nil {
			return fmt.Errorf("failed to load snapshot: %w", err)
		}

		eng := engine.NewEngine(globalTimeout, 10)
		checks.RegisterAll(eng)

		liveReport, err := eng.Run(context.Background(), domain, customResolver)
		if err != nil {
			return fmt.Errorf("live scan failed: %w", err)
		}

		diffReport := diff.CompareSnapshotToLive(snap, liveReport)
		fmt.Println(diffReport.FormatTerminal())
		return nil
	},
}

func init() {
	snapshotCmd.Flags().StringVarP(&snapshotOutputFile, "output", "o", "", "output file path (default: <domain>-snapshot.json)")
}
