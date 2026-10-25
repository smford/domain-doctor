package cli

import (
	"testing"

	"github.com/smford/domain-doctor/internal/engine"
)

func TestComputeHealthScore(t *testing.T) {
	// Case 1: All PASS -> 100 A+
	rep1 := &engine.DiagnosticReport{
		Findings: []engine.Finding{
			{Severity: engine.SeverityPass},
			{Severity: engine.SeverityPass},
		},
	}
	score1, grade1 := ComputeHealthScore(rep1)
	if score1 != 100 || grade1 != "A+" {
		t.Fatalf("expected 100 A+, got %d %s", score1, grade1)
	}

	// Case 2: One Warning -> 90 A
	rep2 := &engine.DiagnosticReport{
		Findings: []engine.Finding{
			{Severity: engine.SeverityWarning},
		},
	}
	score2, grade2 := ComputeHealthScore(rep2)
	if score2 != 90 || grade2 != "A" {
		t.Fatalf("expected 90 A, got %d %s", score2, grade2)
	}

	// Case 3: One Critical, One Warning -> 65 D
	rep3 := &engine.DiagnosticReport{
		Findings: []engine.Finding{
			{Severity: engine.SeverityCritical},
			{Severity: engine.SeverityWarning},
		},
	}
	score3, grade3 := ComputeHealthScore(rep3)
	if score3 != 65 || grade3 != "D" {
		t.Fatalf("expected 65 D, got %d %s", score3, grade3)
	}
}
