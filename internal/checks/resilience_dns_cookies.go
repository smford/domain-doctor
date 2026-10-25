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

type DNSCookiesCheck struct{}

func (c *DNSCookiesCheck) Name() string     { return "resilience_dns_cookies" }
func (c *DNSCookiesCheck) Category() string { return "Resilience" }

func (c *DNSCookiesCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	if len(execCtx.Nameservers) == 0 {
		return nil
	}

	cookieEnabled := make([]string, 0)
	cookieMissing := make([]string, 0)

	// Generate 8-byte random client cookie
	clientBytes := make([]byte, 8)
	_, _ = rand.Read(clientBytes)
	clientCookieHex := hex.EncodeToString(clientBytes)

	for _, ns := range execCtx.Nameservers {
		_, serverCookie, _, err := execCtx.DNSProber.QueryWithCookie(ns, execCtx.Domain, dns.TypeSOA, clientCookieHex)
		if err == nil && serverCookie != "" {
			cookieEnabled = append(cookieEnabled, ns)
		} else {
			cookieMissing = append(cookieMissing, ns)
		}
	}

	if len(cookieEnabled) > 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNS-COOKIES-SUPPORTED",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  fmt.Sprintf("Authoritative nameserver(s) support DNS Cookies (RFC 7873): [%s]", strings.Join(cookieEnabled, ", ")),
			Detail:   "DNS Cookies provide lightweight transaction security and mitigate spoofing, off-path packet injection, and DNS amplification DDoS attacks.",
		})
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNS-COOKIES-NOT-SUPPORTED",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  "Authoritative nameservers do not return DNS Cookies (RFC 7873 / RFC 8749)",
			Detail:   "Enabling DNS Cookies on authoritative daemons (e.g. BIND, Knot, PowerDNS) provides transaction security against cache poisoning and amplification attacks.",
			Remediation: &engine.Remediation{
				Title:       "Enable DNS Cookies on Authoritative DNS",
				Explanation: "Ensure your authoritative nameservers enable cookie support (RFC 7873) to protect clients against reflection attacks.",
				DocURL:      "https://datatracker.ietf.org/doc/html/rfc7873",
			},
		})
	}

	return nil
}
