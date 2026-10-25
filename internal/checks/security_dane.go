package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type DANECheck struct{}

func (c *DANECheck) Name() string     { return "security_dane" }
func (c *DANECheck) Category() string { return "Security" }

func (c *DANECheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	targets := []string{fmt.Sprintf("_443._tcp.%s", execCtx.Domain)}

	// Also extract MX hostnames if present
	for _, mxRec := range execCtx.Records["MX"] {
		parts := strings.Fields(mxRec)
		if len(parts) >= 2 {
			mxHost := strings.TrimSuffix(parts[1], ".")
			if mxHost != "" && mxHost != "." {
				targets = append(targets, fmt.Sprintf("_25._tcp.%s", mxHost))
			}
		}
	}

	discovered := make([]string, 0)
	for _, target := range targets {
		msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", target, dns.TypeTLSA)
		if err == nil && msg != nil {
			for _, ans := range msg.Answer {
				if tlsa, ok := ans.(*dns.TLSA); ok {
					discovered = append(discovered, fmt.Sprintf("%s (usage=%d, selector=%d, match=%d)", target, tlsa.Usage, tlsa.Selector, tlsa.MatchingType))
					execCtx.AddRecord("TLSA", fmt.Sprintf("%s: %s", target, tlsa.String()))
				}
			}
		}
	}

	// Check if DNSSEC is active
	hasDNSSEC := len(execCtx.Records["DNSKEY"]) > 0 || len(execCtx.Records["DS"]) > 0

	if len(discovered) > 0 {
		if !hasDNSSEC {
			execCtx.AddFinding(engine.Finding{
				ID:       "DANE-WITHOUT-DNSSEC",
				Category: c.Category(),
				Severity: engine.SeverityCritical,
				Summary:  fmt.Sprintf("DANE TLSA records published without active DNSSEC on zone (%s)", strings.Join(discovered, ", ")),
				Detail:   "DANE relies entirely on DNSSEC cryptographic chain-of-trust to guarantee authenticity. Without DNSSEC, TLSA records can be intercepted or forged.",
			})
		} else {
			execCtx.AddFinding(engine.Finding{
				ID:       "DANE-TLSA-ACTIVE",
				Category: c.Category(),
				Severity: engine.SeverityPass,
				Summary:  fmt.Sprintf("DANE TLSA authentication active on [%s]", strings.Join(discovered, ", ")),
				Detail:   "Authenticates TLS service certificates directly against DNSSEC-signed records, mitigating Certificate Authority compromise or rogue issuance.",
			})
		}
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "DANE-NOT-CONFIGURED",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  "DANE TLSA (RFC 6698 / RFC 7671) records not published",
			Detail:   "Services rely exclusively on WebPKI Certificate Authorities without DNSSEC-backed certificate or public key pinning.",
			Remediation: &engine.Remediation{
				Title:       "Publish DANE TLSA Records",
				RecordType:  "TLSA",
				Suggested:   fmt.Sprintf("_25._tcp.mail.%s. IN TLSA 3 1 1 <sha256-hash>", execCtx.Domain),
				Explanation: "Publish TLSA records for mail servers (port 25) or web services (port 443) under a DNSSEC-signed zone.",
				DocURL:      "https://datatracker.ietf.org/doc/html/rfc6698",
			},
		})
	}

	return nil
}
