package checks

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/smford/domain-doctor/internal/engine"
)

type CookieScopeCheck struct{}

func (c *CookieScopeCheck) Name() string     { return "security_cookie_scope" }
func (c *CookieScopeCheck) Category() string { return "Security" }

var sensitiveCookieKeywords = []string{
	"session", "sess", "token", "auth", "jwt", "sid", "csrf", "xsrf", "login", "secret", "user",
}

func isSensitiveCookie(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range sensitiveCookieKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func (c *CookieScopeCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	// Probe HTTPS endpoint
	targetURL := fmt.Sprintf("https://%s/", execCtx.Domain)
	client := &http.Client{
		Timeout: 4 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			// Don't follow off-domain redirects
			if !strings.HasSuffix(req.URL.Host, execCtx.Domain) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "domain-doctor/0.1.0 (cookie-scope-audit)")

	resp, err := client.Do(req)
	if err != nil {
		// Try www subdomain as fallback
		fallbackURL := fmt.Sprintf("https://www.%s/", execCtx.Domain)
		fallbackReq, fbErr := http.NewRequestWithContext(ctx, "GET", fallbackURL, nil)
		if fbErr == nil {
			fallbackReq.Header.Set("User-Agent", "domain-doctor/0.1.0 (cookie-scope-audit)")
			resp, err = client.Do(fallbackReq)
		}
		if err != nil || resp == nil {
			return nil
		}
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "COOKIE-NONE-SET",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  "No HTTP Set-Cookie headers returned on initial web landing page",
			Detail:   "The apex endpoint does not issue stateful cookies on initial visit.",
		})
		return nil
	}

	cookieNames := make([]string, 0, len(cookies))
	hasSupercookie := false
	hasPrefixViolation := false
	hasOverScoped := false
	hasSameSiteInsecure := false

	for _, ck := range cookies {
		cookieNames = append(cookieNames, ck.Name)

		// 1. Supercookie Check (Domain matching Public Suffix)
		if ck.Domain != "" {
			cleanDomain := strings.TrimPrefix(ck.Domain, ".")
			ps, _ := publicsuffix.PublicSuffix(cleanDomain)
			if ps == cleanDomain {
				hasSupercookie = true
				execCtx.AddFinding(engine.Finding{
					ID:       "COOKIE-SUPERCOOKIE-REJECTED",
					Category: c.Category(),
					Severity: engine.SeverityCritical,
					Summary:  fmt.Sprintf("Server attempts to set Supercookie on Public Suffix '%s' (cookie: %s)", ck.Domain, ck.Name),
					Detail:   fmt.Sprintf("Browsers strictly drop cookies scoped to a Public Suffix per RFC 6265bis §5.4. Setting Domain=%s is rejected and breaks state persistence.", ck.Domain),
					Remediation: &engine.Remediation{
						Title:       "Scope Cookie to Registered Domain",
						Explanation: fmt.Sprintf("Remove Domain=%s or scope the cookie to an individual eTLD+1 organizational domain.", ck.Domain),
						DocURL:      "https://datatracker.ietf.org/doc/html/rfc6265bis#section-5.4",
					},
				})
			}
		}

		// 2. Cookie Prefix Enforcement: __Host- (RFC 6265bis §4.1.3.2)
		if strings.HasPrefix(ck.Name, "__Host-") {
			if ck.Domain != "" {
				hasPrefixViolation = true
				execCtx.AddFinding(engine.Finding{
					ID:       "COOKIE-HOST-PREFIX-VIOLATION",
					Category: c.Category(),
					Severity: engine.SeverityCritical,
					Summary:  fmt.Sprintf("__Host- cookie '%s' specifies a Domain attribute ('%s')", ck.Name, ck.Domain),
					Detail:   "RFC 6265bis requires __Host- cookies to be strictly Host-Only (must omit Domain attribute). Browsers unconditionally reject this cookie.",
					Remediation: &engine.Remediation{
						Title:       "Remove Domain Attribute from __Host- Cookie",
						Explanation: "Omit the Domain attribute to comply with browser __Host- prefix restrictions.",
						DocURL:      "https://datatracker.ietf.org/doc/html/rfc6265bis#section-4.1.3.2",
					},
				})
			}
			if !ck.Secure {
				hasPrefixViolation = true
				execCtx.AddFinding(engine.Finding{
					ID:       "COOKIE-HOST-NOT-SECURE",
					Category: c.Category(),
					Severity: engine.SeverityCritical,
					Summary:  fmt.Sprintf("__Host- cookie '%s' is missing required Secure attribute", ck.Name),
					Detail:   "RFC 6265bis requires __Host- cookies to be delivered with the Secure flag.",
				})
			}
			if ck.Path != "/" {
				execCtx.AddFinding(engine.Finding{
					ID:       "COOKIE-HOST-INVALID-PATH",
					Category: c.Category(),
					Severity: engine.SeverityWarning,
					Summary:  fmt.Sprintf("__Host- cookie '%s' path is '%s' (must be '/')", ck.Name, ck.Path),
					Detail:   "RFC 6265bis mandates Path=/ for __Host- prefixed cookies.",
				})
			}
		}

		// 3. Cookie Prefix Enforcement: __Secure- (RFC 6265bis §4.1.3.1)
		if strings.HasPrefix(ck.Name, "__Secure-") {
			if !ck.Secure {
				hasPrefixViolation = true
				execCtx.AddFinding(engine.Finding{
					ID:       "COOKIE-SECURE-PREFIX-VIOLATION",
					Category: c.Category(),
					Severity: engine.SeverityCritical,
					Summary:  fmt.Sprintf("__Secure- cookie '%s' missing required Secure flag", ck.Name),
					Detail:   "Browsers unconditionally reject __Secure- cookies without the Secure attribute.",
				})
			}
		}

		// 4. Over-scoped Domain Attribute on Sensitive Cookies
		if ck.Domain != "" && isSensitiveCookie(ck.Name) {
			hasOverScoped = true
			execCtx.AddFinding(engine.Finding{
				ID:       "COOKIE-OVERSCOPED-DOMAIN",
				Category: c.Category(),
				Severity: engine.SeverityWarning,
				Summary:  fmt.Sprintf("Sensitive cookie '%s' is over-scoped to subdomains via Domain=%s", ck.Name, ck.Domain),
				Detail:   fmt.Sprintf("When Domain=%s is set, any current or future subdomain (*.%s) can read or overwrite this cookie. Omit the Domain attribute to enforce a Host-Only cookie restricted exclusively to this specific FQDN.", ck.Domain, ck.Domain),
				Remediation: &engine.Remediation{
					Title:       "Convert to Host-Only Cookie",
					Explanation: "Omit the Domain attribute in Set-Cookie headers so only the exact originating hostname can access the cookie.",
					DocURL:      "https://datatracker.ietf.org/doc/html/rfc6265bis#section-4.1.2.3",
				},
			})
		}

		// 5. SameSite and Transport Hygiene
		if ck.SameSite == http.SameSiteNoneMode && !ck.Secure {
			hasSameSiteInsecure = true
			execCtx.AddFinding(engine.Finding{
				ID:       "COOKIE-SAMESITE-NONE-INSECURE",
				Category: c.Category(),
				Severity: engine.SeverityCritical,
				Summary:  fmt.Sprintf("Cookie '%s' has SameSite=None without Secure flag", ck.Name),
				Detail:   "Chrome, Firefox, and Safari reject any cookie marked SameSite=None that lacks the Secure attribute.",
			})
		}

		if isSensitiveCookie(ck.Name) && !ck.HttpOnly {
			execCtx.AddFinding(engine.Finding{
				ID:       "COOKIE-HTTPONLY-MISSING",
				Category: c.Category(),
				Severity: engine.SeverityWarning,
				Summary:  fmt.Sprintf("Sensitive session cookie '%s' is missing HttpOnly flag", ck.Name),
				Detail:   "Without HttpOnly, JavaScript document.cookie can read this token, exposing users to session hijacking via Cross-Site Scripting (XSS).",
			})
		}
	}

	if !hasSupercookie && !hasPrefixViolation && !hasOverScoped && !hasSameSiteInsecure {
		execCtx.AddFinding(engine.Finding{
			ID:       "COOKIE-HYGIENE-HEALTHY",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  fmt.Sprintf("HTTP Set-Cookie headers conform to RFC 6265bis and PSL scoping (%s)", strings.Join(cookieNames, ", ")),
			Detail:   "Cookies correctly adhere to Public Suffix boundaries, host-only containment, and modern transport security flags.",
		})
	}

	return nil
}
