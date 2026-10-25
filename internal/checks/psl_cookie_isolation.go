package checks

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/smford/domain-doctor/internal/engine"
)

type PSLCookieIsolationCheck struct{}

func (c *PSLCookieIsolationCheck) Name() string     { return "psl_cookie_isolation" }
func (c *PSLCookieIsolationCheck) Category() string { return "Security" }

func (c *PSLCookieIsolationCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(execCtx.Domain)
	if err != nil {
		// Scanned domain is a public suffix itself; covered by psl_boundary
		return nil
	}

	// Determine if domain itself is registered in the Public Suffix List (e.g. *.github.io)
	probeSub := "tenant-isolation-probe." + execCtx.Domain
	childSuffix, _ := publicsuffix.PublicSuffix(probeSub)
	isRegisteredPSL := strings.EqualFold(childSuffix, execCtx.Domain)

	// Check if wildcard DNS was detected by dns_wildcard check
	hasWildcard := false
	for _, f := range execCtx.Findings {
		if f.ID == "DNS-WILDCARD-DETECTED" {
			hasWildcard = true
			break
		}
	}

	if isRegisteredPSL {
		execCtx.AddFinding(engine.Finding{
			ID:       "PSL-COOKIE-ISOLATION-ACTIVE",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  fmt.Sprintf("Domain '%s' is registered in the Public Suffix List Private Section", execCtx.Domain),
			Detail:   "Modern web browsers prevent any subdomain (*." + execCtx.Domain + ") from setting supercookies scoped to the parent domain, enforcing strict cross-tenant session and cookie isolation.",
		})
		return nil
	}

	if hasWildcard {
		execCtx.AddFinding(engine.Finding{
			ID:       "PSL-COOKIE-TOSSING-EXPOSURE",
			Category: c.Category(),
			Severity: engine.SeverityWarning,
			Summary:  fmt.Sprintf("Wildcard DNS active on '%s' without Public Suffix List private boundary registration", execCtx.Domain),
			Detail:   fmt.Sprintf("Because '%s' is an eTLD+1 rather than a registered Public Suffix, browsers allow any tenant subdomain (*.%s) to set cookies with 'Domain=.%s'. If untrusted users or customers control subdomains, they can perform session fixation, cookie tossing, and CSRF token overwriting against other tenants and the apex application. Furthermore, all subdomains share Let's Encrypt's 50 certs/week rate limit.", execCtx.Domain, execCtx.Domain, execCtx.Domain),
			Remediation: &engine.Remediation{
				Title:       "Isolate Multi-Tenant User Content or Submit to PSL",
				Explanation: "Host untrusted or user-generated content on a dedicated sandbox domain (e.g., how Google uses googleusercontent.com and GitHub uses githubassets.com), or submit your multi-tenant domain suffix to the Public Suffix List Private Section.",
				DocURL:      "https://publicsuffix.org/submit/",
			},
		})
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "PSL-STANDARD-COOKIE-BOUNDARY",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  fmt.Sprintf("Organizational cookie boundary cleanly anchored to eTLD+1 '%s'", eTLDPlusOne),
			Detail:   "Browsers restrict supercookie injection above this domain level, and explicit subdomains follow standard same-site cookie partitioning.",
		})
	}

	return nil
}
