package diagram

import (
	"strings"
	"testing"

	"github.com/smford/domain-doctor/internal/engine"
)

func TestMermaidDiagrams(t *testing.T) {
	report := &engine.DiagnosticReport{
		Domain:      "example.com",
		Nameservers: []string{"ns1.example.com", "ns2.example.com"},
		Records: map[string][]string{
			"SPF": {"v=spf1 include:_spf.google.com ~all"},
		},
	}

	delegation := GenerateDelegation(report)
	if !strings.HasPrefix(delegation, "flowchart TD") || !strings.Contains(delegation, "ns1.example.com") {
		t.Fatalf("unexpected delegation diagram: %s", delegation)
	}

	spfDiag := GenerateSPF(report)
	if !strings.HasPrefix(spfDiag, "flowchart TD") || !strings.Contains(spfDiag, "include:_spf.google.com") {
		t.Fatalf("unexpected SPF diagram: %s", spfDiag)
	}

	mailDiag := GenerateMailFlow(report)
	if !strings.HasPrefix(mailDiag, "flowchart LR") || !strings.Contains(mailDiag, "DMARC Alignment Gate") {
		t.Fatalf("unexpected mail flow diagram: %s", mailDiag)
	}
}
