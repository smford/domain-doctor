package checks

import (
	"context"
	"fmt"

	"golang.org/x/net/publicsuffix"

	"github.com/smford/domain-doctor/internal/engine"
)

type PSLBoundaryCheck struct{}

func (c *PSLBoundaryCheck) ID() string       { return "DD-REG-001" }
func (c *PSLBoundaryCheck) Name() string     { return "psl_boundary" }
func (c *PSLBoundaryCheck) Category() string { return "Registration" }

func (c *PSLBoundaryCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	suffix, isICANN := publicsuffix.PublicSuffix(execCtx.Domain)
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(execCtx.Domain)

	// Case 1: Scanned target is itself a Public Suffix / eTLD (e.g. "co.uk", "github.io", "com")
	if err != nil {
		suffixType := "Private Platform Suffix"
		if isICANN {
			suffixType = "ICANN Registry TLD/ccTLD"
		}
		execCtx.AddFinding(engine.Finding{
			ID:       "PSL-DIRECT-SUFFIX-SCANNED",
			Category: c.Category(),
			Severity: engine.SeverityCritical,
			Summary:  fmt.Sprintf("Scanned target is an active Public Suffix / eTLD (%s, Type: %s)", execCtx.Domain, suffixType),
			Detail:   "The target domain is a public registration boundary, not a registrable organizational domain. End-users cannot register this name directly, and browser cookie isolation treats it as a shared public suffix.",
			Remediation: &engine.Remediation{
				Title:       "Scan Registrable Domain (eTLD+1)",
				Explanation: "Run domain-doctor against an individual registered domain under this suffix rather than the public suffix itself.",
				DocURL:      "https://publicsuffix.org/learn/",
			},
		})
		return nil
	}

	// Case 2: Target is an eTLD+1 (the apex organizational domain)
	if eTLDPlusOne == execCtx.Domain {
		if !isICANN {
			// e.g. "tenant.github.io" or "mybrand.azurewebsites.net"
			execCtx.AddFinding(engine.Finding{
				ID:       "PSL-PRIVATE-SUFFIX-TENANT",
				Category: c.Category(),
				Severity: engine.SeverityInfo,
				Summary:  fmt.Sprintf("Domain is registered under a Private Public Suffix platform (%s)", suffix),
				Detail:   fmt.Sprintf("Browsers treat '%s' as an isolated eTLD+1 boundary, protecting you from sibling tenant cookie tampering. However, apex-level DNSSEC and parent CAA policies are governed by the platform provider.", execCtx.Domain),
			})
		} else {
			// Standard ICANN registered domain, e.g. "example.com" or "example.co.uk"
			execCtx.AddFinding(engine.Finding{
				ID:       "PSL-ORGANIZATIONAL-APEX",
				Category: c.Category(),
				Severity: engine.SeverityPass,
				Summary:  fmt.Sprintf("Domain is a valid ICANN organizational domain (eTLD+1: %s, Public Suffix: %s)", execCtx.Domain, suffix),
				Detail:   "Browser cookie jars, SameSite boundaries, and DMARC organizational policies correctly anchor to this domain boundary.",
			})
		}
		return nil
	}

	// Case 3: Target is a deep subdomain (e.g. "api.staging.example.com")
	execCtx.AddFinding(engine.Finding{
		ID:       "PSL-SUBDOMAIN-DETECTED",
		Category: c.Category(),
		Severity: engine.SeverityInfo,
		Summary:  fmt.Sprintf("Target is a subdomain under organizational domain '%s' (eTLD: %s)", eTLDPlusOne, suffix),
		Detail:   fmt.Sprintf("Cookies scoped to '.%s' will be accessible to this subdomain. DMARC policies will inherit from '%s' unless explicit subdomain policies (sp tag) are published.", eTLDPlusOne, eTLDPlusOne),
	})

	return nil
}
