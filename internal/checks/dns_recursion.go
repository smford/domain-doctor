package checks

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type RecursionCheck struct{}

func (c *RecursionCheck) Name() string     { return "dns_recursion" }
func (c *RecursionCheck) Category() string { return "DNS" }

func (c *RecursionCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	if len(execCtx.Nameservers) == 0 {
		return nil
	}

	recursiveServers := make([]string, 0)

	for _, ns := range execCtx.Nameservers {
		ips, err := net.LookupHost(ns)
		if err != nil || len(ips) == 0 {
			continue
		}

		targetIP := ips[0]
		// Query external zone with RecursionDesired=true
		msg, _, err := execCtx.DNSProber.QueryRecursive(targetIP, "google.com", dns.TypeA)
		if err == nil && msg != nil {
			if msg.RecursionAvailable && len(msg.Answer) > 0 {
				recursiveServers = append(recursiveServers, ns)
			}
		}
	}

	if len(recursiveServers) > 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNS-OPEN-RECURSION",
			Category: c.Category(),
			Severity: engine.SeverityCritical,
			Summary:  "Open DNS Recursion and Amplification vector detected",
			Detail:   fmt.Sprintf("Nameservers %s resolved external queries with Recursion Available (RA) bit set. This allows attackers to weaponize your nameservers for DNS amplification DDoS attacks.", strings.Join(recursiveServers, ", ")),
			Remediation: &engine.Remediation{
				Title:       "Disable Recursion on Authoritative Nameservers",
				Explanation: "Configure 'recursion no;' in BIND named.conf or disable recursion in DNS server configuration.",
				DocURL:      "https://kb.isc.org/docs/aa-00269",
			},
		})
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNS-RECURSION-CLOSED",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  "Open recursion disabled across authoritative nameservers",
			Detail:   "Authoritative nameservers correctly reject recursive queries for external zones.",
		})
	}

	return nil
}
