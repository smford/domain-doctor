package checks

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type CDNOriginCheck struct{}

func (c *CDNOriginCheck) ID() string       { return "DD-SEC-008" }
func (c *CDNOriginCheck) Name() string     { return "security_cdn_origin" }
func (c *CDNOriginCheck) Category() string { return "Security" }

var knownCDNCIDRs = []string{
	// Cloudflare
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	// Fastly
	"151.101.0.0/16", "199.232.0.0/16",
	// CloudFront
	"13.32.0.0/15", "13.224.0.0/14", "13.35.0.0/16", "18.64.0.0/14",
	"99.84.0.0/16", "143.204.0.0/16", "205.251.192.0/19",
}

func isCDNIP(ipStr string) bool {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return false
	}
	for _, cidr := range knownCDNCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.Contains(parsed) {
			return true
		}
	}
	return false
}

func (c *CDNOriginCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	// Query Apex A records
	msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", execCtx.Domain, dns.TypeA)
	if err != nil || msg == nil {
		return nil
	}

	apexIPs := make([]string, 0)
	apexBehindCDN := false

	for _, ans := range msg.Answer {
		if a, ok := ans.(*dns.A); ok {
			ip := a.A.String()
			apexIPs = append(apexIPs, ip)
			if isCDNIP(ip) {
				apexBehindCDN = true
			}
		}
	}

	if !apexBehindCDN {
		execCtx.AddFinding(engine.Finding{
			ID:       "CDN-NOT-DETECTED",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  fmt.Sprintf("Apex domain resolves directly to hosting infrastructure ([%s], non-CDN)", strings.Join(apexIPs, ", ")),
			Detail:   "Traffic is routed directly without an intermediary reverse-proxy CDN or cloud WAF.",
		})
		return nil
	}

	// If behind CDN, probe common bypass subdomains
	leakCandidates := []string{
		"direct." + execCtx.Domain,
		"origin." + execCtx.Domain,
		"cpanel." + execCtx.Domain,
		"mail." + execCtx.Domain,
		"ftp." + execCtx.Domain,
	}

	exposedSubdomains := make([]string, 0)
	for _, sub := range leakCandidates {
		subMsg, _, subErr := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", sub, dns.TypeA)
		if subErr == nil && subMsg != nil {
			for _, ans := range subMsg.Answer {
				if a, ok := ans.(*dns.A); ok {
					ip := a.A.String()
					if !isCDNIP(ip) {
						exposedSubdomains = append(exposedSubdomains, fmt.Sprintf("%s (%s)", sub, ip))
					}
				}
			}
		}
	}

	if len(exposedSubdomains) > 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "CDN-ORIGIN-BYPASS-EXPOSED",
			Category: c.Category(),
			Severity: engine.SeverityCritical,
			Summary:  fmt.Sprintf("Direct origin bypass subdomain(s) detected leaking backend IP: [%s]", strings.Join(exposedSubdomains, ", ")),
			Detail:   "Attackers can send requests directly to the discovered IP addresses, completely bypassing Cloudflare/CDN DDoS mitigation, WAF filtering, and rate limiting.",
			Remediation: &engine.Remediation{
				Title:       "Close Direct Origin DNS Records",
				RecordType:  "A",
				Explanation: "Delete unproxied DNS records like origin.* or direct.*, restrict origin firewall rules to only accept traffic from CDN IP blocks, or place administration ports behind a VPN.",
				DocURL:      "https://developers.cloudflare.com/fundamentals/concepts/origin-server-security/",
			},
		})
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "CDN-ORIGIN-PROTECTED",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  "Apex web endpoints are protected behind reverse proxy CDN/WAF with no exposed direct origin subdomains detected",
			Detail:   "Common origin leak vectors (direct.*, origin.*, cpanel.*) cleanly returned either CDN proxies or NXDOMAIN.",
		})
	}

	return nil
}
