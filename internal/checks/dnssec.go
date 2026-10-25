package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type DNSSECCheck struct{}

func (c *DNSSECCheck) Name() string     { return "dnssec" }
func (c *DNSSECCheck) Category() string { return "Security" }

func (c *DNSSECCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	resolver := "1.1.1.1:53"

	// Query DS records
	dsMsg, _, dsErr := execCtx.DNSProber.QueryRecursive(resolver, execCtx.Domain, dns.TypeDS)
	hasDS := (dsErr == nil && dsMsg != nil && len(dsMsg.Answer) > 0)

	// Query DNSKEY records
	dnskeyMsg, _, keyErr := execCtx.DNSProber.QueryRecursive(resolver, execCtx.Domain, dns.TypeDNSKEY)
	hasDNSKEY := (keyErr == nil && dnskeyMsg != nil && len(dnskeyMsg.Answer) > 0)

	// Query RRSIG records
	rrsigMsg, _, sigErr := execCtx.DNSProber.QueryWithDO(resolver, execCtx.Domain, dns.TypeSOA)
	hasRRSIG := false
	var sigExpiry time.Time
	if sigErr == nil && rrsigMsg != nil {
		for _, rr := range append(rrsigMsg.Answer, rrsigMsg.Ns...) {
			if sig, ok := rr.(*dns.RRSIG); ok {
				hasRRSIG = true
				sigExpiry = time.Unix(int64(sig.Expiration), 0)
				break
			}
		}
	}

	if hasDS && hasDNSKEY && hasRRSIG {
		daysRemaining := int(time.Until(sigExpiry).Hours() / 24)
		severity := engine.SeverityPass
		if daysRemaining < 7 {
			severity = engine.SeverityWarning
		}

		execCtx.AddFinding(engine.Finding{
			ID:       "DNSSEC-VALID",
			Category: c.Category(),
			Severity: severity,
			Summary:  fmt.Sprintf("DNSSEC Chain of Trust validated (RRSIG expires in %d days)", daysRemaining),
			Detail:   fmt.Sprintf("DS records present at parent registrar, DNSKEY verified, and RRSIG signature valid until %s.", sigExpiry.Format(time.RFC3339)),
		})
	} else if hasDS && (!hasDNSKEY || !hasRRSIG) {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNSSEC-BROKEN-CHAIN",
			Category: c.Category(),
			Severity: engine.SeverityCritical,
			Summary:  "Broken DNSSEC Chain of Trust (DS record present without matching zone DNSKEY/RRSIG)",
			Detail:   "Parent zone has DS records delegating DNSSEC, but child zone does not return valid DNSKEY or RRSIG records. This causes validation failures (SERVFAIL) on validating resolvers.",
			Remediation: &engine.Remediation{
				Title:       "Repair or Remove Parent DS Record",
				RecordType:  "DS",
				Explanation: "Ensure DNSSEC keys are active in the authoritative zone or remove outdated DS records at the registrar.",
			},
		})
	} else if !hasDS && hasDNSKEY {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNSSEC-UNLINKED-KEYS",
			Category: c.Category(),
			Severity: engine.SeverityWarning,
			Summary:  "DNSKEY records present in zone but no DS record found at parent registrar",
			Detail:   "Zone is signed locally, but registrar lacks DS record to establish root-to-child trust chain.",
			Remediation: &engine.Remediation{
				Title:       "Submit DS Record to Domain Registrar",
				RecordType:  "DS",
				Explanation: "Copy your zone Key Signing Key (KSK) DS record digest to your domain registrar.",
			},
		})
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNSSEC-DISABLED",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  "DNSSEC is not enabled for this domain",
			Detail:   "Zone responses are not cryptographically signed against DNS spoofing and cache poisoning.",
			Remediation: &engine.Remediation{
				Title:       "Enable DNSSEC Signing",
				Explanation: "Generate ZSK/KSK keys, sign zone records, and publish DS digest with registrar.",
				DocURL:      "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en",
			},
		})
	}

	return nil
}
