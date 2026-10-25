package checks

import (
	"context"
	"testing"

	"github.com/smford/domain-doctor/internal/engine"
)

func TestPSLBoundaryCheck_DirectSuffix(t *testing.T) {
	chk := &PSLBoundaryCheck{}
	execCtx := engine.NewExecutionContext("co.uk", 0)

	err := chk.Run(context.Background(), execCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range execCtx.Findings {
		if f.ID == "PSL-DIRECT-SUFFIX-SCANNED" {
			found = true
			if f.Severity != engine.SeverityCritical {
				t.Errorf("expected critical severity, got %v", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected PSL-DIRECT-SUFFIX-SCANNED finding")
	}
}

func TestPSLBoundaryCheck_OrganizationalApex(t *testing.T) {
	chk := &PSLBoundaryCheck{}
	execCtx := engine.NewExecutionContext("example.co.uk", 0)

	err := chk.Run(context.Background(), execCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range execCtx.Findings {
		if f.ID == "PSL-ORGANIZATIONAL-APEX" {
			found = true
			if f.Severity != engine.SeverityPass {
				t.Errorf("expected pass severity, got %v", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected PSL-ORGANIZATIONAL-APEX finding")
	}
}

func TestPSLBoundaryCheck_PrivateSuffixTenant(t *testing.T) {
	chk := &PSLBoundaryCheck{}
	execCtx := engine.NewExecutionContext("mybrand.github.io", 0)

	err := chk.Run(context.Background(), execCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range execCtx.Findings {
		if f.ID == "PSL-PRIVATE-SUFFIX-TENANT" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PSL-PRIVATE-SUFFIX-TENANT finding")
	}
}

func TestPSLCookieIsolation_WildcardExposure(t *testing.T) {
	chk := &PSLCookieIsolationCheck{}
	execCtx := engine.NewExecutionContext("example.com", 0)
	execCtx.AddFinding(engine.Finding{
		ID:       "DNS-WILDCARD-DETECTED",
		Category: "DNS",
		Severity: engine.SeverityWarning,
		Summary:  "Wildcard DNS detected",
	})

	err := chk.Run(context.Background(), execCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range execCtx.Findings {
		if f.ID == "PSL-COOKIE-TOSSING-EXPOSURE" {
			found = true
			if f.Severity != engine.SeverityWarning {
				t.Errorf("expected warning severity, got %v", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected PSL-COOKIE-TOSSING-EXPOSURE finding")
	}
}
