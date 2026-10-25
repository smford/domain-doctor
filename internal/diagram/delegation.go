package diagram

import (
	"fmt"
	"strings"

	"github.com/smford/domain-doctor/internal/engine"
)

func GenerateDelegation(report *engine.DiagnosticReport) string {
	var b strings.Builder
	b.WriteString("flowchart TD\n")
	b.WriteString("    classDef ok fill:#10b981,stroke:#059669,stroke-width:2px,color:#fff;\n")
	b.WriteString("    classDef err fill:#ef4444,stroke:#dc2626,stroke-width:2px,color:#fff;\n")
	b.WriteString("    classDef node fill:#3b82f6,stroke:#1d4ed8,stroke-width:2px,color:#fff;\n\n")

	b.WriteString("    root[\"Root Hints (ICANN Root)\"]:::node\n")

	parts := strings.Split(report.Domain, ".")
	tld := "TLD"
	if len(parts) >= 2 {
		tld = "." + parts[len(parts)-1]
	}
	b.WriteString(fmt.Sprintf("    tld[\"%s Registry Nameservers\"]:::node\n", tld))
	b.WriteString("    root -->|Delegation| tld\n\n")

	if len(report.Nameservers) == 0 {
		b.WriteString("    no_ns[\"No Authoritative NS Detected\"]:::err\n")
		b.WriteString("    tld -.-> no_ns\n")
	} else {
		for i, ns := range report.Nameservers {
			nodeID := fmt.Sprintf("ns%d", i)
			b.WriteString(fmt.Sprintf("    %s[\"%s\"]:::ok\n", nodeID, ns))
			b.WriteString(fmt.Sprintf("    tld -->|NS Delegation| %s\n", nodeID))
			b.WriteString(fmt.Sprintf("    %s -->|Authoritative Answer AA| apex[\"%s\"]:::node\n", nodeID, report.Domain))
		}
	}

	return b.String()
}
