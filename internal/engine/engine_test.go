package engine

import (
	"context"
	"testing"
	"time"
)

type mockCheck struct {
	id       string
	name     string
	category string
	severity Severity
}

func (m *mockCheck) ID() string       { return m.id }
func (m *mockCheck) Name() string     { return m.name }
func (m *mockCheck) Category() string { return m.category }
func (m *mockCheck) Run(ctx context.Context, execCtx *ExecutionContext) error {
	execCtx.AddFinding(Finding{
		RuleID:   m.id,
		ID:       m.name,
		Category: m.category,
		Severity: m.severity,
		Summary:  "Mock summary",
	})
	return nil
}

func TestEngineExecution(t *testing.T) {
	eng := NewEngine(5*time.Second, 4)
	eng.Register(&mockCheck{id: "DD-DNS-001", name: "MOCK-1", category: "DNS", severity: SeverityPass})
	eng.Register(&mockCheck{id: "DD-MAIL-001", name: "MOCK-2", category: "Mail", severity: SeverityWarning})

	rep, err := eng.Run(context.Background(), "example.com", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}

	if rep.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", rep.Domain)
	}

	found1, found2 := false, false
	for _, f := range rep.Findings {
		if f.ID == "MOCK-1" {
			found1 = true
		}
		if f.ID == "MOCK-2" {
			found2 = true
		}
	}

	if !found1 || !found2 {
		t.Fatalf("expected both mock findings, got %v", rep.Findings)
	}
}

func TestEngineRuleFilterAndOverride(t *testing.T) {
	eng := NewEngine(5*time.Second, 4)
	eng.Register(&mockCheck{id: "DD-DNS-001", name: "MOCK-1", category: "DNS", severity: SeverityPass})
	eng.Register(&mockCheck{id: "DD-MAIL-001", name: "MOCK-2", category: "Mail", severity: SeverityWarning})

	// Filter out Mail
	eng.SetRuleFilter(func(ruleID, category string) bool {
		return category == "DNS"
	})
	// Override DNS severity to Critical
	eng.SetSeverityOverrides(map[string]string{
		"DD-DNS-001": "CRIT",
	})

	rep, err := eng.Run(context.Background(), "example.com", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}

	if len(rep.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding due to filter, got %d", len(rep.Findings))
	}
	if rep.Findings[0].RuleID != "DD-DNS-001" {
		t.Errorf("expected DD-DNS-001, got %s", rep.Findings[0].RuleID)
	}
	if rep.Findings[0].Severity != SeverityCritical {
		t.Errorf("expected severity to be overridden to CRIT, got %s", rep.Findings[0].Severity)
	}
}
