package engine

import (
	"context"
	"testing"
	"time"
)

type mockCheck struct {
	name     string
	category string
	severity Severity
}

func (m *mockCheck) Name() string     { return m.name }
func (m *mockCheck) Category() string { return m.category }
func (m *mockCheck) Run(ctx context.Context, execCtx *ExecutionContext) error {
	execCtx.AddFinding(Finding{
		ID:       m.name,
		Category: m.category,
		Severity: m.severity,
		Summary:  "Mock summary",
	})
	return nil
}

func TestEngineExecution(t *testing.T) {
	eng := NewEngine(5*time.Second, 4)
	eng.Register(&mockCheck{name: "MOCK-1", category: "DNS", severity: SeverityPass})
	eng.Register(&mockCheck{name: "MOCK-2", category: "Mail", severity: SeverityWarning})

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
