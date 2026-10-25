package checks

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/smford/domain-doctor/internal/engine"
)

type ZoneTransferCheck struct{}

func (c *ZoneTransferCheck) ID() string       { return "DD-DNS-002" }
func (c *ZoneTransferCheck) Name() string     { return "dns_zone_transfer" }
func (c *ZoneTransferCheck) Category() string { return "DNS" }

func (c *ZoneTransferCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	if len(execCtx.Nameservers) == 0 {
		return nil
	}

	leakedServers := make([]string, 0)

	for _, ns := range execCtx.Nameservers {
		ips, err := net.LookupHost(ns)
		if err != nil || len(ips) == 0 {
			continue
		}

		targetIP := ips[0]
		allowed, count, _ := execCtx.DNSProber.CheckAXFR(targetIP, execCtx.Domain)
		if allowed {
			leakedServers = append(leakedServers, fmt.Sprintf("%s (%d records)", ns, count))
		}
	}

	if len(leakedServers) > 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNS-AXFR-LEAK",
			Category: c.Category(),
			Severity: engine.SeverityCritical,
			Summary:  "Unrestricted DNS Zone Transfer (AXFR) Leak (RFC 5936)",
			Detail:   fmt.Sprintf("Zone transfer succeeded on: %s. An external attacker can download the complete zone topology and internal host records.", strings.Join(leakedServers, ", ")),
			Remediation: &engine.Remediation{
				Title:       "Restrict Zone Transfers in BIND/DNS Daemon",
				Explanation: "Add 'allow-transfer { none; };' or restrict transfers to authenticated secondary nameserver IPs with TSIG keys.",
				DocURL:      "https://datatracker.ietf.org/doc/html/rfc5936",
			},
		})
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNS-AXFR-SECURE",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  "Zone transfer (AXFR) properly refused on all authoritative nameservers",
			Detail:   "Unauthenticated zone transfer requests were rejected per RFC 5936 recommendations.",
		})
	}

	return nil
}
