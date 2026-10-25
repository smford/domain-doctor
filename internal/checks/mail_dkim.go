package checks

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type DKIMCheck struct{}

func (c *DKIMCheck) ID() string       { return "DD-MAIL-003" }
func (c *DKIMCheck) Name() string     { return "mail_dkim" }
func (c *DKIMCheck) Category() string { return "Mail" }

var CommonDKIMSelectors = []string{
	"default",
	"google",
	"k1",
	"s1",
	"s2",
	"selector1",
	"selector2",
	"mail",
	"mandrill",
	"mailgun",
	"dkim",
	"zoho",
	"protonmail",
}

func (c *DKIMCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	discovered := make([]string, 0)

	for _, selector := range CommonDKIMSelectors {
		sel := selector
		wg.Add(1)
		go func() {
			defer wg.Done()
			qname := fmt.Sprintf("%s._domainkey.%s", sel, execCtx.Domain)
			msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", qname, dns.TypeTXT)
			if err == nil && msg != nil && len(msg.Answer) > 0 {
				for _, ans := range msg.Answer {
					if txt, ok := ans.(*dns.TXT); ok {
						val := strings.Join(txt.Txt, "")
						if strings.Contains(val, "p=") || strings.Contains(val, "v=DKIM1") {
							mu.Lock()
							discovered = append(discovered, sel)
							execCtx.AddRecord("DKIM", fmt.Sprintf("%s: %s", sel, val))
							mu.Unlock()
							break
						}
					}
				}
			}
		}()
	}
	wg.Wait()

	if len(discovered) > 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "DKIM-SELECTORS-DISCOVERED",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  fmt.Sprintf("Active DKIM public keys discovered for selector(s): [%s]", strings.Join(discovered, ", ")),
			Detail:   "Outbound messages signed with these selectors can be cryptographically verified against sender forgery.",
		})
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "DKIM-NO-COMMON-SELECTORS",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  "No standard DKIM selectors discovered via public dictionary scan",
			Detail:   fmt.Sprintf("Probed %d common selectors without finding public keys. Your organization may be using custom or private DKIM selector names.", len(CommonDKIMSelectors)),
			Remediation: &engine.Remediation{
				Title:       "Verify Outbound Mail Signing Keys",
				RecordType:  "TXT",
				Explanation: "Ensure your email sending provider (e.g., Google Workspace, Microsoft 365, SendGrid) has published DKIM public keys.",
				DocURL:      "https://datatracker.ietf.org/doc/html/rfc6376",
			},
		})
	}

	return nil
}
