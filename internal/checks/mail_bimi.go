package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type BIMICheck struct{}

func (c *BIMICheck) ID() string       { return "DD-MAIL-006" }
func (c *BIMICheck) Name() string     { return "mail_bimi" }
func (c *BIMICheck) Category() string { return "Mail" }

func (c *BIMICheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	bimiHost := fmt.Sprintf("default._bimi.%s", execCtx.Domain)
	msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", bimiHost, dns.TypeTXT)

	var bimiRecord string
	if err == nil && msg != nil {
		for _, ans := range msg.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				full := strings.Join(txt.Txt, "")
				if strings.HasPrefix(strings.TrimSpace(full), "v=BIMI1") {
					bimiRecord = full
					execCtx.AddRecord("BIMI", full)
					break
				}
			}
		}
	}

	if bimiRecord == "" {
		execCtx.AddFinding(engine.Finding{
			ID:       "BIMI-NOT-CONFIGURED",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  fmt.Sprintf("BIMI (Brand Indicators for Message Identification) not configured at %s", bimiHost),
			Detail:   "BIMI enables authenticated visual brand logos in supporting mail inboxes (Gmail, Apple Mail, Yahoo) when strict DMARC is enforced.",
			Remediation: &engine.Remediation{
				Title:       "Publish BIMI Record",
				RecordType:  "TXT",
				Suggested:   fmt.Sprintf("default._bimi.%s. IN TXT \"v=BIMI1; l=https://%s/logo.svg; a=https://%s/cert.pem;\"", execCtx.Domain, execCtx.Domain, execCtx.Domain),
				Explanation: "Host an SVG Tiny P-profile logo and obtain a Verified Mark Certificate (VMC) from an authorized authority.",
				DocURL:      "https://bimigroup.org/all-about-bimi/",
			},
		})
		return nil
	}

	// Parse BIMI tags
	tags := make(map[string]string)
	parts := strings.Split(bimiRecord, ";")
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 {
			tags[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
		}
	}

	logoURL := tags["l"]
	vmcURL := tags["a"]

	// Check DMARC compliance requirement
	dmarcRecords := execCtx.Records["DMARC"]
	dmarcStrict := false
	for _, rec := range dmarcRecords {
		if strings.Contains(rec, "p=reject") || (strings.Contains(rec, "p=quarantine") && !strings.Contains(rec, "pct=") || strings.Contains(rec, "pct=100")) {
			dmarcStrict = true
			break
		}
	}

	if !dmarcStrict && len(dmarcRecords) > 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "BIMI-DMARC-INELIGIBLE",
			Category: c.Category(),
			Severity: engine.SeverityWarning,
			Summary:  "BIMI record published but current DMARC policy does not satisfy BIMI eligibility requirements",
			Detail:   "Inbox providers strictly require DMARC policy to be at 'p=reject' or 'p=quarantine' with 'pct=100' for BIMI logos to display.",
		})
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "BIMI-CONFIGURED",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  fmt.Sprintf("BIMI active with brand logo (%s) and certificate (%s)", logoURL, vmcURL),
			Detail:   "Compliant email clients will render authenticated brand iconography next to verified sender messages.",
		})
	}

	return nil
}
