package checks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type DNSDelegationCheck struct{}

func (c *DNSDelegationCheck) Name() string     { return "dns_delegation" }
func (c *DNSDelegationCheck) Category() string { return "DNS" }

func (c *DNSDelegationCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	if len(execCtx.Nameservers) == 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNS-NO-NAMESERVERS",
			Category: c.Category(),
			Severity: engine.SeverityCritical,
			Summary:  "No authoritative nameservers discovered",
			Detail:   fmt.Sprintf("Could not resolve NS records for %s.", execCtx.Domain),
			Remediation: &engine.Remediation{
				Title:       "Configure NS Records at Domain Registrar",
				RecordType:  "NS",
				Explanation: "Ensure your domain has valid nameservers delegated with your registrar.",
			},
		})
		return nil
	}

	execCtx.AddFinding(engine.Finding{
		ID:       "DNS-NS-COUNT",
		Category: c.Category(),
		Severity: func() engine.Severity {
			if len(execCtx.Nameservers) < 2 {
				return engine.SeverityWarning
			}
			return engine.SeverityPass
		}(),
		Summary: fmt.Sprintf("%d authoritative nameservers discovered", len(execCtx.Nameservers)),
		Detail:  fmt.Sprintf("Nameservers: %s", strings.Join(execCtx.Nameservers, ", ")),
		Remediation: func() *engine.Remediation {
			if len(execCtx.Nameservers) < 2 {
				return &engine.Remediation{
					Title:       "Provision Redundant Nameservers",
					RecordType:  "NS",
					Explanation: "RFC 2182 recommends at least two independent authoritative nameservers for resilience.",
				}
			}
			return nil
		}(),
	})

	// Query each authoritative nameserver directly
	type nsResult struct {
		ns     string
		aa     bool
		serial uint32
		rtt    time.Duration
		err    error
	}

	results := make([]nsResult, len(execCtx.Nameservers))
	var wg sync.WaitGroup

	for i, ns := range execCtx.Nameservers {
		idx := i
		nsHost := ns
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Resolve NS IP first
			ips, err := net.LookupHost(nsHost)
			if err != nil || len(ips) == 0 {
				results[idx] = nsResult{ns: nsHost, err: fmt.Errorf("could not resolve IP for %s", nsHost)}
				return
			}

			targetIP := ips[0]
			msg, rtt, err := execCtx.DNSProber.Query(targetIP, execCtx.Domain, dns.TypeSOA)
			if err != nil {
				results[idx] = nsResult{ns: nsHost, err: err}
				return
			}

			if msg.Rcode != dns.RcodeSuccess {
				results[idx] = nsResult{
					ns:  nsHost,
					err: fmt.Errorf("received non-success RCODE %s (%d)", dns.RcodeToString[msg.Rcode], msg.Rcode),
				}
				return
			}

			var serial uint32
			for _, ans := range msg.Answer {
				if soa, ok := ans.(*dns.SOA); ok {
					serial = soa.Serial
					break
				}
			}

			results[idx] = nsResult{
				ns:     nsHost,
				aa:     msg.Authoritative,
				serial: serial,
				rtt:    rtt,
			}
		}()
	}
	wg.Wait()

	serials := make(map[uint32][]string)
	for _, res := range results {
		if res.err != nil {
			execCtx.AddFinding(engine.Finding{
				ID:       "DNS-LAME-DELEGATION",
				Category: c.Category(),
				Severity: engine.SeverityCritical,
				Summary:  fmt.Sprintf("Lame delegation detected on %s", res.ns),
				Detail:   fmt.Sprintf("Authoritative server %s failed to respond: %v", res.ns, res.err),
				Remediation: &engine.Remediation{
					Title:       "Fix or Remove Unresponsive Nameserver",
					RecordType:  "NS",
					Explanation: fmt.Sprintf("Remove %s from domain delegation or repair DNS service daemon.", res.ns),
				},
			})
			continue
		}

		if !res.aa {
			execCtx.AddFinding(engine.Finding{
				ID:       "DNS-NO-AA-BIT",
				Category: c.Category(),
				Severity: engine.SeverityWarning,
				Summary:  fmt.Sprintf("Nameserver %s did not set Authoritative Answer (AA) bit", res.ns),
				Detail:   fmt.Sprintf("Queries to %s returned answers without AA bit set, indicating possible caching proxy behavior.", res.ns),
			})
		}

		if res.serial > 0 {
			serials[res.serial] = append(serials[res.serial], res.ns)
		}
	}

	// Check serial skew
	if len(serials) > 1 {
		detailParts := make([]string, 0)
		for s, servers := range serials {
			detailParts = append(detailParts, fmt.Sprintf("Serial %d: [%s]", s, strings.Join(servers, ", ")))
		}
		execCtx.AddFinding(engine.Finding{
			ID:       "DNS-SOA-SERIAL-SKEW",
			Category: c.Category(),
			Severity: engine.SeverityWarning,
			Summary:  "SOA serial discrepancy across authoritative nameservers",
			Detail:   fmt.Sprintf("Nameservers reported differing SOA serials: %s", strings.Join(detailParts, " | ")),
			Remediation: &engine.Remediation{
				Title:       "Synchronize Secondary Nameservers",
				RecordType:  "SOA",
				Explanation: "Force zone transfer (NOTIFY/AXFR) to ensure all secondaries mirror primary master serial.",
			},
		})
	} else if len(serials) == 1 {
		for s := range serials {
			execCtx.AddFinding(engine.Finding{
				ID:       "DNS-SOA-SYNC",
				Category: c.Category(),
				Severity: engine.SeverityPass,
				Summary:  fmt.Sprintf("All authoritative nameservers synchronized on SOA serial %d", s),
				Detail:   "Zone propagation across authoritative fleet is consistent.",
			})
		}
	}

	// Check TCP fallback on first working NS
	for _, res := range results {
		if res.err == nil {
			ips, _ := net.LookupHost(res.ns)
			if len(ips) > 0 {
				_, tcpRTT, tcpErr := execCtx.DNSProber.QueryTCP(ips[0], execCtx.Domain, dns.TypeSOA)
				if tcpErr != nil {
					execCtx.AddFinding(engine.Finding{
						ID:       "DNS-TCP-BLOCKED",
						Category: c.Category(),
						Severity: engine.SeverityWarning,
						Summary:  fmt.Sprintf("TCP fallback failed on nameserver %s (port 53/TCP)", res.ns),
						Detail:   fmt.Sprintf("RFC 7766 requires port 53/TCP to be open for large responses and truncation: %v", tcpErr),
						Remediation: &engine.Remediation{
							Title:       "Open Inbound TCP Port 53",
							Explanation: "Ensure firewalls allow TCP port 53 traffic to authoritative nameservers.",
						},
					})
				} else {
					execCtx.AddFinding(engine.Finding{
						ID:       "DNS-TCP-OK",
						Category: c.Category(),
						Severity: engine.SeverityPass,
						Summary:  fmt.Sprintf("TCP fallback functional on port 53 (RTT: %s)", tcpRTT),
						Detail:   "Nameserver correctly accepts TCP connections for EDNS0 buffer overflow protection.",
					})
				}
				break
			}
		}
	}

	// Wildcard resolution probe: random 32-character hex subdomain
	randBytes := make([]byte, 16)
	_, _ = rand.Read(randBytes)
	wildcardSub := fmt.Sprintf("%s.%s", hex.EncodeToString(randBytes), execCtx.Domain)
	wildcardMsg, _, _ := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", wildcardSub, dns.TypeA)
	if wildcardMsg != nil && len(wildcardMsg.Answer) > 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNS-WILDCARD-ACTIVE",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  "Wildcard DNS record detected (*.<domain>)",
			Detail:   fmt.Sprintf("Random subdomain %s resolved to active addresses.", wildcardSub),
		})
	}

	return nil
}
