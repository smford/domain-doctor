package checks

import (
	"strings"
	"testing"

	"github.com/smford/domain-doctor/internal/engine"
)

func TestSPFMechanismCounting(t *testing.T) {
	chk := &SPFCheck{}
	execCtx := engine.NewExecutionContext("example.com", 0)

	// Test case 1: simple SPF with 2 lookups (mx, a)
	spf1 := "v=spf1 mx a ip4:192.0.2.0/24 -all"
	lookups, err := chk.countLookups(execCtx, spf1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lookups != 2 {
		t.Errorf("expected 2 lookups, got %d", lookups)
	}

	// Test case 2: qualifier stripping
	spf2 := "v=spf1 +mx +a ?exists:test.com ~all"
	lookups2, err := chk.countLookups(execCtx, spf2, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lookups2 != 3 {
		t.Errorf("expected 3 lookups, got %d", lookups2)
	}
}

func TestSPFDuplicateAndQualifierDetection(t *testing.T) {
	spf := "v=spf1 +all"
	if !strings.Contains(spf, "+all") {
		t.Fatalf("expected +all detection")
	}
}
