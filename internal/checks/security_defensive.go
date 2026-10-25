package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type DefensiveDomainCheck struct{}

func (c *DefensiveDomainCheck) ID() string       { return "DD-SEC-007" }
func (c *DefensiveDomainCheck) Name() string     { return "security_defensive" }
func (c *DefensiveDomainCheck) Category() string { return "Security" }

func (c *DefensiveDomainCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	// Query MX records
	mxMsg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", execCtx.Domain, dns.TypeMX)

	hasNullMX := false
	hasAnyMX := false

	if err == nil && mxMsg != nil {
		for _, ans := range mxMsg.Answer {
			if mx, ok := ans.(*dns.MX); ok {
				hasAnyMX = true
				if mx.Preference == 0 && (mx.Mx == "." || mx.Mx == "") {
					hasNullMX = true
					break
				}
			}
		}
	}

	// Check SPF
	hasHardFailSPF := false
	for _, rec := range execCtx.Records["SPF"] {
		clean := strings.TrimSpace(rec)
		if strings.HasPrefix(clean, "v=spf1") && (clean == "v=spf1 -all" || strings.HasSuffix(clean, "-all")) && !strings.Contains(clean, "+all") && !strings.Contains(clean, "~all") {
			hasHardFailSPF = true
			break
		}
	}

	// Check DMARC
	hasStrictDMARC := false
	for _, rec := range execCtx.Records["DMARC"] {
		if strings.Contains(rec, "p=reject") && (strings.Contains(rec, "sp=reject") || !strings.Contains(rec, "sp=")) {
			hasStrictDMARC = true
			break
		}
	}

	if hasNullMX {
		if hasHardFailSPF && hasStrictDMARC {
			execCtx.AddFinding(engine.Finding{
				ID:       "DEFENSIVE-KILLSWITCH-OPTIMAL",
				Category: c.Category(),
				Severity: engine.SeverityPass,
				Summary:  "Defensive domain email killswitch is fully configured (RFC 7505 Null MX + Hard-fail SPF + Strict DMARC)",
				Detail:   "Inbound mail delivery is unconditionally rejected, and outbound mail spoofing across all sending MTAs is prevented.",
			})
		} else {
			execCtx.AddFinding(engine.Finding{
				ID:       "DEFENSIVE-KILLSWITCH-INCOMPLETE",
				Category: c.Category(),
				Severity: engine.SeverityWarning,
				Summary:  "Null MX (RFC 7505) is configured, but outbound SPF or DMARC policies are not set to hard reject",
				Detail:   "While incoming mail is rejected, spammers can still spoof outbound emails from this domain unless SPF is 'v=spf1 -all' and DMARC is 'p=reject'.",
				Remediation: &engine.Remediation{
					Title:       "Harden Defensive SPF and DMARC",
					RecordType:  "TXT",
					Suggested:   fmt.Sprintf("%s. IN TXT \"v=spf1 -all\"\n_dmarc.%s. IN TXT \"v=DMARC1; p=reject; sp=reject; aspf=s; adkim=s;\"", execCtx.Domain, execCtx.Domain),
					Explanation: "Publish strict hard-fail SPF and reject DMARC to close outbound spoofing vectors.",
					DocURL:      "https://datatracker.ietf.org/doc/html/rfc7505",
				},
			})
		}
	} else if !hasAnyMX {
		// Domain has no MX records at all
		execCtx.AddFinding(engine.Finding{
			ID:       "NO-MX-DEFENSIVE-ADVISORY",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  "Domain publishes no MX records; if non-sending, consider publishing an RFC 7505 Null MX record",
			Detail:   "Under RFC 5321 §5.1, mail servers fall back to the apex A/AAAA record when no MX is published. If this domain never receives email, publishing 'MX 0 .' stops unsolicited delivery attempts.",
			Remediation: &engine.Remediation{
				Title:       "Publish RFC 7505 Null MX",
				RecordType:  "MX",
				Suggested:   fmt.Sprintf("%s. IN MX 0 .", execCtx.Domain),
				Explanation: "An MX record with preference 0 and target '.' tells all SMTP clients that this domain explicitly does not accept email.",
				DocURL:      "https://datatracker.ietf.org/doc/html/rfc7505",
			},
		})
	}

	return nil
}
