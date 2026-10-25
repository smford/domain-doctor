package iac

import (
	"fmt"
	"strings"
	"time"

	"github.com/smford/domain-doctor/internal/engine"
)

func ExportBIND(report *engine.DiagnosticReport) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("; BIND Zone File for %s\n", report.Domain))
	b.WriteString(fmt.Sprintf("; Exported by domain-doctor on %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString("$TTL 3600\n")
	b.WriteString(fmt.Sprintf("@ IN SOA ns1.%s. hostmaster.%s. (\n", report.Domain, report.Domain))
	b.WriteString("    2026102501 ; Serial\n")
	b.WriteString("    7200       ; Refresh\n")
	b.WriteString("    3600       ; Retry\n")
	b.WriteString("    1209600    ; Expire\n")
	b.WriteString("    3600 )     ; Minimum\n\n")

	// NS records
	for _, ns := range report.Nameservers {
		b.WriteString(fmt.Sprintf("@ IN NS %s.\n", ns))
	}
	b.WriteString("\n")

	// Other discovered records
	for rtype, rrs := range report.Records {
		if rtype == "NS" || rtype == "SOA" {
			continue
		}
		for _, rr := range rrs {
			b.WriteString(fmt.Sprintf("@ IN %s %s\n", rtype, rr))
		}
	}

	return b.String()
}
