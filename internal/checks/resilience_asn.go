package checks

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type ASNDiversityCheck struct{}

func (c *ASNDiversityCheck) Name() string     { return "resilience_asn" }
func (c *ASNDiversityCheck) Category() string { return "Resilience" }

func (c *ASNDiversityCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	if len(execCtx.Nameservers) == 0 {
		return nil
	}

	asns := make(map[string][]string) // ASN -> list of NS
	subnets := make(map[string][]string)

	for _, ns := range execCtx.Nameservers {
		ips, err := net.LookupIP(ns)
		if err != nil || len(ips) == 0 {
			continue
		}

		for _, ip := range ips {
			ipv4 := ip.To4()
			if ipv4 != nil {
				// /24 subnet check
				subnet := fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], ipv4[2])
				subnets[subnet] = append(subnets[subnet], ns)

				// Team Cymru DNS IP-to-ASN mapping: reversed octets .origin.asn.cymru.com
				cymruQuery := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", ipv4[3], ipv4[2], ipv4[1], ipv4[0])
				msg, _, qErr := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", cymruQuery, dns.TypeTXT)
				if qErr == nil && msg != nil && len(msg.Answer) > 0 {
					for _, ans := range msg.Answer {
						if txt, ok := ans.(*dns.TXT); ok && len(txt.Txt) > 0 {
							// Format: "15169 | 8.8.8.0/24 | US | arin | 2014-03-14"
							fields := strings.Split(txt.Txt[0], "|")
							if len(fields) > 0 {
								asn := strings.TrimSpace(fields[0])
								asns["AS"+asn] = append(asns["AS"+asn], ns)
							}
						}
					}
				}
				break
			}
		}
	}

	if len(asns) == 1 && len(execCtx.Nameservers) > 1 {
		for singleASN, servers := range asns {
			execCtx.AddFinding(engine.Finding{
				ID:       "BGP-SINGLE-ASN",
				Category: c.Category(),
				Severity: engine.SeverityWarning,
				Summary:  fmt.Sprintf("Single Point of Failure: All nameservers routed via single BGP Autonomous System (%s)", singleASN),
				Detail:   fmt.Sprintf("All authoritative nameservers [%s] belong to %s. A BGP hijack, route leak, or upstream outage at this ASN would disable DNS resolution for the entire domain.", strings.Join(servers, ", "), singleASN),
				Remediation: &engine.Remediation{
					Title:       "Introduce Secondary DNS Provider on Disjoint BGP ASN",
					Explanation: "Deploy secondary nameservers across a different cloud/DNS provider (e.g., multi-provider Cloudflare + Route53) to eliminate single-ASN routing vulnerability.",
				},
			})
		}
	} else if len(asns) > 1 {
		asnsList := make([]string, 0)
		for a := range asns {
			asnsList = append(asnsList, a)
		}
		execCtx.AddFinding(engine.Finding{
			ID:       "BGP-ASN-DIVERSE",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  fmt.Sprintf("Resilient BGP routing diversity: Authoritative fleet spans %d ASNs (%s)", len(asns), strings.Join(asnsList, ", ")),
			Detail:   "Nameservers are distributed across distinct autonomous systems, protecting against single-provider routing failures.",
		})
	}

	if len(subnets) == 1 && len(execCtx.Nameservers) > 1 {
		for singleSubnet := range subnets {
			execCtx.AddFinding(engine.Finding{
				ID:       "BGP-SINGLE-SUBNET",
				Category: c.Category(),
				Severity: engine.SeverityWarning,
				Summary:  fmt.Sprintf("All authoritative nameservers share a single IPv4 /24 subnet (%s)", singleSubnet),
				Detail:   "Co-locating nameservers in the same /24 IP block creates physical/topological risk to localized datacenter or network fabric failures.",
			})
		}
	}

	return nil
}
