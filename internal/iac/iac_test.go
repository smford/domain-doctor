package iac

import (
	"strings"
	"testing"

	"github.com/smford/domain-doctor/internal/engine"
)

func TestBINDAndTerraformExport(t *testing.T) {
	report := &engine.DiagnosticReport{
		Domain:      "example.com",
		Nameservers: []string{"ns1.example.com", "ns2.example.com"},
		Records: map[string][]string{
			"MX":  {"10 mail.example.com"},
			"SPF": {"v=spf1 -all"},
		},
	}

	bindZone := ExportBIND(report)
	if !strings.Contains(bindZone, "$TTL") || !strings.Contains(bindZone, "@ IN NS ns1.example.com.") {
		t.Fatalf("unexpected BIND output:\n%s", bindZone)
	}

	hcl := ExportTerraformRoute53(report)
	if !strings.Contains(hcl, "resource \"aws_route53_zone\" \"primary\"") || !strings.Contains(hcl, "aws_route53_record\" \"mx\"") {
		t.Fatalf("unexpected HCL output:\n%s", hcl)
	}
}
