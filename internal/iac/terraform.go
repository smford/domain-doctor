package iac

import (
	"fmt"
	"strings"

	"github.com/smford/domain-doctor/internal/engine"
)

func ExportTerraformRoute53(report *engine.DiagnosticReport) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Terraform Route53 Records for %s\n", report.Domain))
	b.WriteString(fmt.Sprintf("resource \"aws_route53_zone\" \"primary\" {\n  name = \"%s\"\n}\n\n", report.Domain))

	// Export MX records
	if mxRecords, ok := report.Records["MX"]; ok && len(mxRecords) > 0 {
		b.WriteString(fmt.Sprintf("resource \"aws_route53_record\" \"mx\" {\n  zone_id = aws_route53_zone.primary.zone_id\n  name    = \"%s\"\n  type    = \"MX\"\n  ttl     = 300\n  records = [\n", report.Domain))
		for _, mx := range mxRecords {
			b.WriteString(fmt.Sprintf("    \"%s\",\n", mx))
		}
		b.WriteString("  ]\n}\n\n")
	}

	// Export SPF / TXT records
	if spfRecords, ok := report.Records["SPF"]; ok && len(spfRecords) > 0 {
		b.WriteString(fmt.Sprintf("resource \"aws_route53_record\" \"spf\" {\n  zone_id = aws_route53_zone.primary.zone_id\n  name    = \"%s\"\n  type    = \"TXT\"\n  ttl     = 300\n  records = [\n", report.Domain))
		for _, spf := range spfRecords {
			b.WriteString(fmt.Sprintf("    \"%s\",\n", spf))
		}
		b.WriteString("  ]\n}\n\n")
	}

	// Export DMARC
	if dmarcRecords, ok := report.Records["DMARC"]; ok && len(dmarcRecords) > 0 {
		b.WriteString(fmt.Sprintf("resource \"aws_route53_record\" \"dmarc\" {\n  zone_id = aws_route53_zone.primary.zone_id\n  name    = \"_dmarc.%s\"\n  type    = \"TXT\"\n  ttl     = 300\n  records = [\n    \"%s\",\n  ]\n}\n\n", report.Domain, dmarcRecords[0]))
	}

	return b.String()
}
