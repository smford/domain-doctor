package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type CAACheck struct{}

func (c *CAACheck) Name() string     { return "security_caa" }
func (c *CAACheck) Category() string { return "Security" }

func (c *CAACheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", execCtx.Domain, dns.TypeCAA)
	if err != nil || msg == nil || len(msg.Answer) == 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "CAA-RECORDS-MISSING",
			Category: c.Category(),
			Severity: engine.SeverityWarning,
			Summary:  "Certificate Authority Authorization (CAA) records missing",
			Detail:   "Without CAA records, any public CA trusted by operating systems and browsers can issue certificates for your domain.",
			Remediation: &engine.Remediation{
				Title:       "Publish CAA Records",
				RecordType:  "CAA",
				Suggested:   fmt.Sprintf("%s. IN CAA 0 issue \"letsencrypt.org\"\n%s. IN CAA 0 iodef \"mailto:security@%s\"", execCtx.Domain, execCtx.Domain, execCtx.Domain),
				Explanation: "Explicitly designate authorized CAs (e.g., letsencrypt.org, digicert.com) and configure incident reporting via iodef.",
				DocURL:      "https://datatracker.ietf.org/doc/html/rfc8659",
			},
		})
		return nil
	}

	caaTags := make([]string, 0)
	hasIssue := false
	hasIodef := false

	for _, ans := range msg.Answer {
		if caa, ok := ans.(*dns.CAA); ok {
			execCtx.AddRecord("CAA", fmt.Sprintf("%d %s \"%s\"", caa.Flag, caa.Tag, caa.Value))
			caaTags = append(caaTags, fmt.Sprintf("%s=%s", caa.Tag, caa.Value))
			if caa.Tag == "issue" || caa.Tag == "issuewild" {
				hasIssue = true
			}
			if caa.Tag == "iodef" {
				hasIodef = true
			}
		}
	}

	if hasIssue {
		execCtx.AddFinding(engine.Finding{
			ID:       "CAA-CONFIGURED",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  fmt.Sprintf("CAA policy enforces authorized Certificate Authorities (%s)", strings.Join(caaTags, ", ")),
			Detail:   "Compliant Certificate Authorities are strictly bounded by your published issuer policy.",
		})
	}

	if !hasIodef {
		execCtx.AddFinding(engine.Finding{
			ID:       "CAA-IODEF-MISSING",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  "CAA record does not specify an incident reporting URI (iodef tag)",
			Detail:   "Adding an 'iodef' tag allows compliant CAs to notify your security team if an unauthorized certificate request is attempted.",
		})
	}

	return nil
}
