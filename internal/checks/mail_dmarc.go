package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/smford/domain-doctor/internal/engine"
)

type DMARCCheck struct{}

func (c *DMARCCheck) Name() string     { return "mail_dmarc" }
func (c *DMARCCheck) Category() string { return "Mail" }

func (c *DMARCCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	resolver := "1.1.1.1:53"
	dmarcDomain := "_dmarc." + execCtx.Domain

	msg, _, err := execCtx.DNSProber.QueryRecursive(resolver, dmarcDomain, dns.TypeTXT)

	var dmarcRecord string
	if err == nil && msg != nil && len(msg.Answer) > 0 {
		for _, ans := range msg.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				val := strings.Join(txt.Txt, "")
				if strings.HasPrefix(strings.TrimSpace(val), "v=DMARC1") {
					dmarcRecord = val
					break
				}
			}
		}
	}

	// Organizational domain fallback via publicsuffix
	if dmarcRecord == "" {
		eTLDPlus1, psErr := publicsuffix.EffectiveTLDPlusOne(execCtx.Domain)
		if psErr == nil && eTLDPlus1 != execCtx.Domain {
			orgDMARCDomain := "_dmarc." + eTLDPlus1
			orgMsg, _, orgErr := execCtx.DNSProber.QueryRecursive(resolver, orgDMARCDomain, dns.TypeTXT)
			if orgErr == nil && orgMsg != nil && len(orgMsg.Answer) > 0 {
				for _, ans := range orgMsg.Answer {
					if txt, ok := ans.(*dns.TXT); ok {
						val := strings.Join(txt.Txt, "")
						if strings.HasPrefix(strings.TrimSpace(val), "v=DMARC1") {
							dmarcRecord = val
							execCtx.AddFinding(engine.Finding{
								ID:       "DMARC-ORG-FALLBACK",
								Category: c.Category(),
								Severity: engine.SeverityInfo,
								Summary:  fmt.Sprintf("Inheriting DMARC policy from organizational domain (%s)", eTLDPlus1),
								Detail:   fmt.Sprintf("Explicit _dmarc.%s record not found; falling back to %s per RFC 7489 §6.6.3.", execCtx.Domain, val),
							})
							break
						}
					}
				}
			}
		}
	}

	if dmarcRecord == "" {
		execCtx.AddFinding(engine.Finding{
			ID:       "DMARC-MISSING",
			Category: c.Category(),
			Severity: engine.SeverityCritical,
			Summary:  "DMARC policy record missing (_dmarc.<domain>)",
			Detail:   "Without DMARC, receiving email providers cannot verify SPF and DKIM alignment, leaving your brand exposed to domain impersonation and phishing.",
			Remediation: &engine.Remediation{
				Title:       "Publish DMARC TXT Record",
				RecordType:  "TXT",
				Suggested:   fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@%s\"", execCtx.Domain, execCtx.Domain),
				Explanation: "Publish a DMARC policy with quarantine or reject enforcement and configure rua reporting.",
				DocURL:      "https://dmarc.org/overview/",
			},
		})
	} else {
		execCtx.AddRecord("DMARC", dmarcRecord)
		tags := parseTags(dmarcRecord)

		policy := tags["p"]
		rua := tags["rua"]

		switch strings.ToLower(policy) {
		case "reject":
			execCtx.AddFinding(engine.Finding{
				ID:       "DMARC-POLICY-REJECT",
				Category: c.Category(),
				Severity: engine.SeverityPass,
				Summary:  "Strong DMARC policy configured (p=reject)",
				Detail:   fmt.Sprintf("Unauthenticated spoofed messages will be outright rejected by mail receivers: %s", dmarcRecord),
			})
		case "quarantine":
			execCtx.AddFinding(engine.Finding{
				ID:       "DMARC-POLICY-QUARANTINE",
				Category: c.Category(),
				Severity: engine.SeverityPass,
				Summary:  "Enforcing DMARC policy configured (p=quarantine)",
				Detail:   "Unauthenticated messages are delivered to spam/junk quarantine.",
			})
		case "none":
			execCtx.AddFinding(engine.Finding{
				ID:       "DMARC-POLICY-NONE",
				Category: c.Category(),
				Severity: engine.SeverityWarning,
				Summary:  "Permissive DMARC policy in monitor-only mode (p=none)",
				Detail:   "A policy of 'p=none' provides aggregate reporting but does not prevent spammers from spoofing your domain.",
				Remediation: &engine.Remediation{
					Title:       "Upgrade DMARC Policy to Quarantine or Reject",
					RecordType:  "TXT",
					Explanation: "Transition policy from p=none to p=quarantine, then p=reject once legitimate sending sources are aligned.",
				},
			})
		default:
			execCtx.AddFinding(engine.Finding{
				ID:       "DMARC-INVALID-POLICY",
				Category: c.Category(),
				Severity: engine.SeverityCritical,
				Summary:  fmt.Sprintf("Invalid or missing 'p=' tag in DMARC record: %s", dmarcRecord),
				Detail:   "RFC 7489 requires a valid 'p=' tag with none, quarantine, or reject.",
			})
		}

		if rua == "" {
			execCtx.AddFinding(engine.Finding{
				ID:       "DMARC-RUA-MISSING",
				Category: c.Category(),
				Severity: engine.SeverityWarning,
				Summary:  "DMARC aggregate reporting address (rua) missing",
				Detail:   "Without an 'rua=mailto:...' URI, you will not receive forensic XML reports detailing who is sending email from your domain.",
			})
		}
	}

	// Probe MTA-STS, TLS-RPT, and BIMI
	c.checkMTASTS(execCtx)
	c.checkTLSRPT(execCtx)
	c.checkBIMI(execCtx)

	return nil
}

func (c *DMARCCheck) checkMTASTS(execCtx *engine.ExecutionContext) {
	msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", "_mta-sts."+execCtx.Domain, dns.TypeTXT)
	if err == nil && msg != nil && len(msg.Answer) > 0 {
		for _, ans := range msg.Answer {
			if txt, ok := ans.(*dns.TXT); ok && strings.HasPrefix(strings.Join(txt.Txt, ""), "v=STSv1") {
				execCtx.AddFinding(engine.Finding{
					ID:       "MTA-STS-PRESENT",
					Category: c.Category(),
					Severity: engine.SeverityPass,
					Summary:  "MTA-STS (RFC 8461) record published",
					Detail:   fmt.Sprintf("Record: %s", strings.Join(txt.Txt, "")),
				})
				return
			}
		}
	}
}

func (c *DMARCCheck) checkTLSRPT(execCtx *engine.ExecutionContext) {
	msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", "_smtp._tls."+execCtx.Domain, dns.TypeTXT)
	if err == nil && msg != nil && len(msg.Answer) > 0 {
		for _, ans := range msg.Answer {
			if txt, ok := ans.(*dns.TXT); ok && strings.HasPrefix(strings.Join(txt.Txt, ""), "v=TLSRPTv1") {
				execCtx.AddFinding(engine.Finding{
					ID:       "TLS-RPT-PRESENT",
					Category: c.Category(),
					Severity: engine.SeverityPass,
					Summary:  "SMTP TLS Reporting (RFC 8460) enabled",
					Detail:   fmt.Sprintf("Record: %s", strings.Join(txt.Txt, "")),
				})
				return
			}
		}
	}
}

func (c *DMARCCheck) checkBIMI(execCtx *engine.ExecutionContext) {
	msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", "default._bimi."+execCtx.Domain, dns.TypeTXT)
	if err == nil && msg != nil && len(msg.Answer) > 0 {
		for _, ans := range msg.Answer {
			if txt, ok := ans.(*dns.TXT); ok && strings.HasPrefix(strings.Join(txt.Txt, ""), "v=BIMI1") {
				execCtx.AddFinding(engine.Finding{
					ID:       "BIMI-PRESENT",
					Category: c.Category(),
					Severity: engine.SeverityPass,
					Summary:  "BIMI (Brand Indicators for Message Identification) record detected",
					Detail:   fmt.Sprintf("Record: %s", strings.Join(txt.Txt, "")),
				})
				return
			}
		}
	}
}

func parseTags(raw string) map[string]string {
	tags := make(map[string]string)
	parts := strings.Split(raw, ";")
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 {
			tags[strings.ToLower(kv[0])] = kv[1]
		}
	}
	return tags
}
