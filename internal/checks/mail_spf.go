package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type SPFCheck struct{}

func (c *SPFCheck) ID() string       { return "DD-MAIL-001" }
func (c *SPFCheck) Name() string     { return "mail_spf" }
func (c *SPFCheck) Category() string { return "Mail" }

func (c *SPFCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", execCtx.Domain, dns.TypeTXT)
	if err != nil || msg == nil {
		return nil
	}

	spfRecords := make([]string, 0)
	for _, ans := range msg.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			combined := strings.Join(txt.Txt, "")
			if strings.HasPrefix(strings.TrimSpace(combined), "v=spf1") {
				spfRecords = append(spfRecords, combined)
				execCtx.AddRecord("SPF", combined)
			}
		}
	}

	if len(spfRecords) == 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "SPF-MISSING",
			Category: c.Category(),
			Severity: engine.SeverityCritical,
			Summary:  "Sender Policy Framework (SPF) record missing",
			Detail:   "No v=spf1 TXT record found. Malicious senders can easily spoof emails from your domain.",
			Remediation: &engine.Remediation{
				Title:       "Publish SPF TXT Record",
				RecordType:  "TXT",
				Suggested:   "v=spf1 include:_spf.google.com ~all",
				Explanation: "Define legitimate sending IP addresses/services and terminate with ~all or -all.",
				DocURL:      "https://datatracker.ietf.org/doc/html/rfc7208",
			},
		})
		return nil
	}

	if len(spfRecords) > 1 {
		execCtx.AddFinding(engine.Finding{
			ID:       "SPF-DUPLICATE",
			Category: c.Category(),
			Severity: engine.SeverityCritical,
			Summary:  fmt.Sprintf("Multiple SPF records found (%d records)", len(spfRecords)),
			Detail:   "RFC 7208 §3.2 states that a domain MUST NOT have more than one SPF record. Multiple records result in immediate PermError on receiving mail transfer agents.",
			Remediation: &engine.Remediation{
				Title:       "Consolidate into Single SPF Record",
				RecordType:  "TXT",
				Explanation: "Merge all mechanisms from the separate SPF strings into a single v=spf1 TXT record.",
			},
		})
	}

	spfRecord := spfRecords[0]

	// Check terminating qualifier
	if strings.Contains(spfRecord, "+all") {
		execCtx.AddFinding(engine.Finding{
			ID:       "SPF-PLUS-ALL",
			Category: c.Category(),
			Severity: engine.SeverityCritical,
			Summary:  "SPF policy configured with '+all' (Permissive Pass-All)",
			Detail:   "'+all' explicitly authorizes the entire internet to send email on behalf of your domain.",
			Remediation: &engine.Remediation{
				Title:       "Replace '+all' with Softfail or Hardfail",
				RecordType:  "TXT",
				Suggested:   strings.Replace(spfRecord, "+all", "~all", 1),
				Explanation: "Use '~all' (softfail) or '-all' (hardfail) to enforce sender domain authentication.",
			},
		})
	} else if strings.Contains(spfRecord, "?all") {
		execCtx.AddFinding(engine.Finding{
			ID:       "SPF-NEUTRAL-ALL",
			Category: c.Category(),
			Severity: engine.SeverityWarning,
			Summary:  "SPF policy ends with '?all' (Neutral)",
			Detail:   "Neutral policy instructs receivers not to enforce SPF evaluation. Switch to ~all or -all.",
		})
	}

	// Calculate recursive DNS lookup mechanisms
	totalLookups, err := c.countLookups(execCtx, spfRecord, 0)
	if err != nil {
		execCtx.AddFinding(engine.Finding{
			ID:       "SPF-LOOKUP-RECURSION-LOOP",
			Category: c.Category(),
			Severity: engine.SeverityCritical,
			Summary:  "SPF lookup recursion error or circular dependency",
			Detail:   err.Error(),
		})
		return nil
	}

	if totalLookups > 10 {
		execCtx.AddFinding(engine.Finding{
			ID:       "SPF-LOOKUP-LIMIT-EXCEEDED",
			Category: c.Category(),
			Severity: engine.SeverityCritical,
			Summary:  fmt.Sprintf("SPF lookup limit exceeded: %d mechanisms (Maximum is 10)", totalLookups),
			Detail:   "RFC 7208 §4.6.4 limits SPF lookups to 10. Exceeding this limit triggers an immediate PermError, causing legitimate emails to be marked as spam or rejected.",
			Remediation: &engine.Remediation{
				Title:       "Flatten SPF Records",
				RecordType:  "TXT",
				Explanation: "Use IP prefixes (ip4/ip6) instead of includes, or use dynamic SPF flattening tools to stay under the 10-lookup ceiling.",
				DocURL:      "https://dmarcian.com/spf-syntax-table/",
			},
		})
	} else if totalLookups >= 8 {
		execCtx.AddFinding(engine.Finding{
			ID:       "SPF-LOOKUP-LIMIT-WARNING",
			Category: c.Category(),
			Severity: engine.SeverityWarning,
			Summary:  fmt.Sprintf("SPF lookup count high: %d mechanisms (Approaching 10 limit)", totalLookups),
			Detail:   "Any additional include or MX mechanism could easily push SPF evaluation over the RFC 7208 PermError threshold.",
		})
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "SPF-LOOKUP-COUNT-HEALTHY",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  fmt.Sprintf("SPF record lookup count healthy (%d / 10 allowed)", totalLookups),
			Detail:   fmt.Sprintf("SPF mechanism: %s", spfRecord),
		})
	}

	return nil
}

func (c *SPFCheck) countLookups(execCtx *engine.ExecutionContext, spf string, depth int) (int, error) {
	if depth > 10 {
		return 0, fmt.Errorf("spf evaluation recursion depth exceeded")
	}

	tokens := strings.Fields(spf)
	lookups := 0

	for _, token := range tokens {
		clean := strings.ToLower(token)
		clean = strings.TrimPrefix(clean, "+")
		clean = strings.TrimPrefix(clean, "-")
		clean = strings.TrimPrefix(clean, "~")
		clean = strings.TrimPrefix(clean, "?")

		if strings.HasPrefix(clean, "include:") {
			lookups++
			target := strings.TrimPrefix(clean, "include:")
			msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", target, dns.TypeTXT)
			if err == nil && msg != nil {
				for _, ans := range msg.Answer {
					if txt, ok := ans.(*dns.TXT); ok {
						subSPF := strings.Join(txt.Txt, "")
						if strings.HasPrefix(strings.TrimSpace(subSPF), "v=spf1") {
							subLookups, subErr := c.countLookups(execCtx, subSPF, depth+1)
							if subErr == nil {
								lookups += subLookups
							}
						}
					}
				}
			}
		} else if strings.HasPrefix(clean, "redirect=") {
			lookups++
		} else if clean == "a" || strings.HasPrefix(clean, "a:") || strings.HasPrefix(clean, "a/") {
			lookups++
		} else if clean == "mx" || strings.HasPrefix(clean, "mx:") || strings.HasPrefix(clean, "mx/") {
			lookups++
		} else if clean == "ptr" || strings.HasPrefix(clean, "ptr:") {
			lookups++
		} else if strings.HasPrefix(clean, "exists:") {
			lookups++
		}
	}

	return lookups, nil
}
