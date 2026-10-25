package diagram

import (
	"fmt"
	"strings"

	"github.com/smford/domain-doctor/internal/engine"
)

func GenerateMailFlow(report *engine.DiagnosticReport) string {
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	b.WriteString("    classDef auth fill:#10b981,stroke:#059669,stroke-width:2px,color:#fff;\n")
	b.WriteString("    classDef gate fill:#8b5cf6,stroke:#6d28d9,stroke-width:2px,color:#fff;\n")
	b.WriteString("    classDef dkim fill:#3b82f6,stroke:#1d4ed8,stroke-width:2px,color:#fff;\n")
	b.WriteString("    classDef spf fill:#06b6d4,stroke:#0891b2,stroke-width:2px,color:#fff;\n")
	b.WriteString("    classDef dest fill:#1f2937,stroke:#111827,stroke-width:2px,color:#fff;\n\n")

	b.WriteString(fmt.Sprintf("    subgraph Sources [\"%s Senders\"]\n", report.Domain))
	b.WriteString("        mx[\"Inbound/Outbound MX\"]\n")
	b.WriteString("        spf[\"SPF Authorized IPs\"]:::spf\n")
	b.WriteString("        dkim[\"DKIM Signed Selectors\"]:::dkim\n")
	b.WriteString("    end\n\n")

	b.WriteString("    gate{\"DMARC Alignment Gate\"}:::gate\n")
	b.WriteString("    inbox[\"Recipient Inbox\"]:::auth\n")
	b.WriteString("    reject[\"Quarantine / Reject\"]:::dest\n\n")

	b.WriteString("    spf -->|SPF Alignment Check| gate\n")
	b.WriteString("    dkim -->|DKIM Crypto Verification| gate\n")
	b.WriteString("    mx -.->|SMTP Transport| gate\n\n")

	b.WriteString("    gate -->|Aligned: SPF or DKIM Match| inbox\n")
	b.WriteString("    gate -->|Unaligned / Spoofed| reject\n")

	return b.String()
}
