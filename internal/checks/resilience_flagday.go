package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type FlagDayCheck struct{}

func (c *FlagDayCheck) Name() string     { return "resilience_flagday" }
func (c *FlagDayCheck) Category() string { return "Resilience" }

func (c *FlagDayCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	if len(execCtx.Nameservers) == 0 {
		return nil
	}

	oversizedServers := make([]string, 0)
	compliantServers := make([]string, 0)
	noEDNSServers := make([]string, 0)

	for _, ns := range execCtx.Nameservers {
		in, _, err := execCtx.DNSProber.QueryWithCustomEDNS(ns, execCtx.Domain, dns.TypeSOA, 1232, false)
		if err != nil || in == nil {
			continue
		}

		opt := in.IsEdns0()
		if opt == nil {
			noEDNSServers = append(noEDNSServers, ns)
			continue
		}

		udpSize := opt.UDPSize()
		if udpSize > 1472 {
			oversizedServers = append(oversizedServers, fmt.Sprintf("%s (%d bytes)", ns, udpSize))
		} else {
			compliantServers = append(compliantServers, fmt.Sprintf("%s (%d bytes)", ns, udpSize))
		}
	}

	if len(noEDNSServers) > 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "EDNS-NOT-SUPPORTED",
			Category: c.Category(),
			Severity: engine.SeverityCritical,
			Summary:  fmt.Sprintf("Authoritative nameserver(s) failed EDNS0 negotiation: [%s]", strings.Join(noEDNSServers, ", ")),
			Detail:   "EDNS0 (RFC 6891) is mandatory for modern DNS operations, DNSSEC, and large response handling.",
		})
	}

	if len(oversizedServers) > 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNS-FLAGDAY-BUFFER-OVERSIZED",
			Category: c.Category(),
			Severity: engine.SeverityWarning,
			Summary:  fmt.Sprintf("Nameservers advertise EDNS buffer size > 1472 bytes risking IP fragmentation: [%s]", strings.Join(oversizedServers, ", ")),
			Detail:   "Per DNS Flag Day 2020 guidelines, EDNS buffer size should not exceed 1232 bytes (or maximum 1472 bytes) to prevent UDP IP packet fragmentation attacks.",
			Remediation: &engine.Remediation{
				Title:       "Set Authoritative EDNS Buffer Size to 1232",
				Explanation: "Configure authoritative DNS daemons (BIND: max-udp-size 1232; NSD: max-udp-size 1232) to limit UDP buffer size and avoid fragmentation attacks.",
				DocURL:      "https://dnsflagday.net/2020/",
			},
		})
	} else if len(compliantServers) > 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNS-FLAGDAY-COMPLIANT",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  fmt.Sprintf("Authoritative nameservers comply with DNS Flag Day 2020 fragmentation standards: [%s]", strings.Join(compliantServers, ", ")),
			Detail:   "EDNS0 buffer sizes prevent UDP packet fragmentation over typical MTU path bottlenecks.",
		})
	}

	return nil
}
