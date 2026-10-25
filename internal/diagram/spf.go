package diagram

import (
	"fmt"
	"strings"

	"github.com/smford/domain-doctor/internal/engine"
)

func GenerateSPF(report *engine.DiagnosticReport) string {
	var b strings.Builder
	b.WriteString("flowchart TD\n")
	b.WriteString("    classDef ok fill:#10b981,stroke:#059669,stroke-width:2px,color:#fff;\n")
	b.WriteString("    classDef warn fill:#f59e0b,stroke:#d97706,stroke-width:2px,color:#fff;\n")
	b.WriteString("    classDef err fill:#ef4444,stroke:#dc2626,stroke-width:2px,color:#fff;\n")
	b.WriteString("    classDef root fill:#3b82f6,stroke:#1d4ed8,stroke-width:2px,color:#fff;\n\n")

	b.WriteString(fmt.Sprintf("    domain[\"%s\"]:::root\n", report.Domain))

	spfRecords := report.Records["SPF"]
	if len(spfRecords) == 0 {
		b.WriteString("    no_spf[\"No SPF Record Configured\"]:::err\n")
		b.WriteString("    domain --> no_spf\n")
		return b.String()
	}

	spf := spfRecords[0]
	tokens := strings.Fields(spf)
	lookupCount := 0

	for i, token := range tokens {
		clean := strings.ToLower(token)
		isInclude := strings.HasPrefix(clean, "include:")
		isMechanism := isInclude || clean == "a" || clean == "mx" || strings.HasPrefix(clean, "a:") || strings.HasPrefix(clean, "mx:")

		if isMechanism {
			lookupCount++
		}

		nodeID := fmt.Sprintf("node_%d", i)
		nodeClass := "ok"
		if lookupCount > 10 {
			nodeClass = "err"
		} else if lookupCount >= 8 {
			nodeClass = "warn"
		}

		label := token
		if isMechanism {
			label = fmt.Sprintf("%s (Lookup #%d)", token, lookupCount)
			if lookupCount > 10 {
				label = fmt.Sprintf("%s [PermError > 10!]", token)
			}
		}

		b.WriteString(fmt.Sprintf("    %s[\"%s\"]:::%s\n", nodeID, label, nodeClass))
		b.WriteString(fmt.Sprintf("    domain --> %s\n", nodeID))
	}

	return b.String()
}
