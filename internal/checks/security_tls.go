package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
	"github.com/smford/domain-doctor/internal/prober"
)

type TLSHealthCheck struct{}

func (c *TLSHealthCheck) Name() string     { return "security_tls" }
func (c *TLSHealthCheck) Category() string { return "Security" }

func (c *TLSHealthCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	// 1. Check apex CNAME violation (RFC 1034 §3.6.2)
	cnameMsg, _, _ := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", execCtx.Domain, dns.TypeCNAME)
	if cnameMsg != nil && len(cnameMsg.Answer) > 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNS-APEX-CNAME-VIOLATION",
			Category: c.Category(),
			Severity: engine.SeverityCritical,
			Summary:  "Apex CNAME record violates RFC 1034 §3.6.2",
			Detail:   "A CNAME record at zone apex conflicts with required SOA and NS records. Use ANAME, ALIAS, or Cloudflare CNAME flattening instead.",
		})
	}

	targets := []string{execCtx.Domain, "www." + execCtx.Domain}

	for _, target := range targets {
		tlsCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		res, err := prober.ProbeTLS(tlsCtx, target, 443, target, 3*time.Second)
		cancel()

		if err != nil {
			// Some domains do not host web on www or apex
			execCtx.AddFinding(engine.Finding{
				ID:       fmt.Sprintf("TLS-CONN-FAILED-%s", strings.ReplaceAll(target, ".", "-")),
				Category: c.Category(),
				Severity: engine.SeverityInfo,
				Summary:  fmt.Sprintf("HTTPS connection not established on %s:443", target),
				Detail:   fmt.Sprintf("Probe note: %v. (Normal if this host is not configured to serve HTTPS web traffic).", err),
			})
			continue
		}

		if !res.Verified {
			execCtx.AddFinding(engine.Finding{
				ID:       fmt.Sprintf("TLS-CERT-INVALID-%s", strings.ReplaceAll(target, ".", "-")),
				Category: c.Category(),
				Severity: engine.SeverityCritical,
				Summary:  fmt.Sprintf("TLS Certificate validation failed on %s", target),
				Detail:   fmt.Sprintf("Verification error: %v", res.VerifyError),
				Remediation: &engine.Remediation{
					Title:       "Renew or Replace Invalid TLS Certificate",
					Explanation: "Ensure certificate is issued by a publicly trusted CA and hostname matches SANs.",
				},
			})
			continue
		}

		// Certificate expiration check
		if res.DaysToExpiry < 3 {
			execCtx.AddFinding(engine.Finding{
				ID:       fmt.Sprintf("TLS-EXPIRY-CRITICAL-%s", strings.ReplaceAll(target, ".", "-")),
				Category: c.Category(),
				Severity: engine.SeverityCritical,
				Summary:  fmt.Sprintf("TLS Certificate on %s expires in %d days!", target, res.DaysToExpiry),
				Detail:   fmt.Sprintf("Subject: %s. Immediate renewal required to prevent browser security warnings and site downtime.", res.Certificates[0].Subject.CommonName),
			})
		} else if res.DaysToExpiry < 14 {
			execCtx.AddFinding(engine.Finding{
				ID:       fmt.Sprintf("TLS-EXPIRY-WARNING-%s", strings.ReplaceAll(target, ".", "-")),
				Category: c.Category(),
				Severity: engine.SeverityWarning,
				Summary:  fmt.Sprintf("TLS Certificate on %s expires soon (%d days remaining)", target, res.DaysToExpiry),
				Detail:   fmt.Sprintf("Issuer: %s. Verify automated renewal (e.g. ACME/Certbot) is scheduled.", res.Certificates[0].Issuer.CommonName),
			})
		} else {
			execCtx.AddFinding(engine.Finding{
				ID:       fmt.Sprintf("TLS-HEALTHY-%s", strings.ReplaceAll(target, ".", "-")),
				Category: c.Category(),
				Severity: engine.SeverityPass,
				Summary:  fmt.Sprintf("Valid TLS certificate active on %s (%d days remaining)", target, res.DaysToExpiry),
				Detail:   fmt.Sprintf("SANs: %s | Issuer: %s", strings.Join(res.Certificates[0].DNSNames, ", "), res.Certificates[0].Issuer.CommonName),
			})
		}
	}

	return nil
}
