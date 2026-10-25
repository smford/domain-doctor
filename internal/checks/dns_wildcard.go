package checks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type WildcardCheck struct{}

func (c *WildcardCheck) ID() string       { return "DD-DNS-005" }
func (c *WildcardCheck) Name() string     { return "dns_wildcard" }
func (c *WildcardCheck) Category() string { return "DNS" }

func (c *WildcardCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	// Generate random non-existent subdomain
	randBytes := make([]byte, 8)
	_, _ = rand.Read(randBytes)
	probeSub := fmt.Sprintf("_wildcard_probe_%s.%s", hex.EncodeToString(randBytes), execCtx.Domain)

	msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", probeSub, dns.TypeA)
	if err != nil || msg == nil {
		return nil
	}

	wildcardTargets := make([]string, 0)
	if msg.Rcode == dns.RcodeSuccess && len(msg.Answer) > 0 {
		for _, ans := range msg.Answer {
			if a, ok := ans.(*dns.A); ok {
				wildcardTargets = append(wildcardTargets, a.A.String())
			} else if cname, ok := ans.(*dns.CNAME); ok {
				wildcardTargets = append(wildcardTargets, cname.Target)
			}
		}
	}

	if len(wildcardTargets) > 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNS-WILDCARD-DETECTED",
			Category: c.Category(),
			Severity: engine.SeverityWarning,
			Summary:  fmt.Sprintf("Wildcard DNS record (*.%s) detected resolving to [%s]", execCtx.Domain, strings.Join(wildcardTargets, ", ")),
			Detail:   "Wildcard DNS resolves arbitrary non-existent subdomains. This complicates dangling CNAME takeover auditing, causes SSL/TLS certificate name mismatches on arbitrary subdomains, and can bypass strict DMARC subdomain policy inheritance.",
			Remediation: &engine.Remediation{
				Title:       "Review and Restrict Wildcard DNS",
				RecordType:  "A/CNAME",
				Explanation: "Ensure wildcard records are strictly intentional. If wildcard routing is not required, delete the '*.' DNS record and declare subdomains explicitly.",
				DocURL:      "https://datatracker.ietf.org/doc/html/rfc4592",
			},
		})
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNS-NO-WILDCARD",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  "No wildcard DNS record detected; domain enforces strict explicit subdomain resolution",
			Detail:   "Non-existent subdomains cleanly return NXDOMAIN, ensuring accurate subdomain isolation and proper negative caching.",
		})
	}

	return nil
}
