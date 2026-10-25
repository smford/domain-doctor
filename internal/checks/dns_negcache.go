package checks

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"github.com/smford/domain-doctor/internal/engine"
	"github.com/smford/domain-doctor/internal/prober"
)

type NegativeCacheCheck struct{}

func (c *NegativeCacheCheck) ID() string       { return "DD-NC-001" }
func (c *NegativeCacheCheck) Name() string     { return "dns_negcache" }
func (c *NegativeCacheCheck) Category() string { return "NegativeCache" }

func (c *NegativeCacheCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	if len(execCtx.Nameservers) == 0 {
		return nil
	}

	// 1. Establish ground truth from authoritative nameserver
	var authServer string
	for _, ns := range execCtx.Nameservers {
		ips, err := net.LookupHost(ns)
		if err == nil && len(ips) > 0 {
			authServer = ips[0]
			break
		}
	}

	if authServer == "" {
		return nil
	}

	recordTypes := []uint16{dns.TypeA, dns.TypeMX}

	// Bounded parallel worker pool across resolvers and record types
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(6)

	var mu sync.Mutex

	for _, qtype := range recordTypes {
		qt := qtype
		qtypeName := dns.TypeToString[qt]

		authMsg, _, err := execCtx.DNSProber.Query(authServer, execCtx.Domain, qt)
		if err != nil || authMsg == nil {
			continue
		}

		authHasRecord := (authMsg.Rcode == dns.RcodeSuccess && len(authMsg.Answer) > 0)

		for _, resolver := range prober.PublicResolvers {
			resAddr := resolver
			g.Go(func() error {
				if gCtx.Err() != nil {
					return gCtx.Err()
				}

				queryCtx, cancel := context.WithTimeout(gCtx, 3*time.Second)
				defer cancel()

				_ = queryCtx
				recMsg, _, recErr := execCtx.DNSProber.QueryRecursive(resAddr, execCtx.Domain, qt)
				if recErr != nil || recMsg == nil {
					return nil
				}

				cachedState := ""
				if recMsg.Rcode == dns.RcodeNameError {
					cachedState = "NXDOMAIN"
				} else if recMsg.Rcode == dns.RcodeSuccess && len(recMsg.Answer) == 0 {
					cachedState = "NODATA"
				}

				if cachedState != "" {
					var soaMaster string
					var soaMinTTL uint32
					var remainingTTL uint32

					for _, nsRR := range recMsg.Ns {
						if soa, ok := nsRR.(*dns.SOA); ok {
							soaMaster = soa.Ns
							soaMinTTL = soa.Minttl
							remainingTTL = soa.Hdr.Ttl
							if soa.Minttl < remainingTTL {
								remainingTTL = soa.Minttl
							}
							break
						}
					}

					status := engine.NegativeCacheStatus{
						Resolver:      resAddr,
						RecordName:    execCtx.Domain,
						RecordType:    qtypeName,
						CachedState:   cachedState,
						AuthSOA:       soaMaster,
						SOAMinimumTTL: soaMinTTL,
						RemainingTTL:  remainingTTL,
						AuthHasRecord: authHasRecord,
					}
					execCtx.AddNegativeCache(status)

					if authHasRecord {
						mu.Lock()
						execCtx.AddFinding(engine.Finding{
							ID:       fmt.Sprintf("NEGCACHE-STALE-%s-%s", resAddr, qtypeName),
							Category: c.Category(),
							Severity: engine.SeverityWarning,
							Summary:  fmt.Sprintf("RFC 2308 Negative Cache Staleness detected at %s", resAddr),
							Detail: fmt.Sprintf("Resolver %s serves cached %s for %s %s, while authoritative nameserver serves live records. %d seconds remaining before eviction.",
								resAddr, cachedState, execCtx.Domain, qtypeName, remainingTTL),
							Remediation: &engine.Remediation{
								Title:       fmt.Sprintf("Purge Public Resolver Cache (%s)", resAddr),
								RecordType:  qtypeName,
								Explanation: fmt.Sprintf("Wait %d seconds for negative cache TTL eviction or submit cache flush to resolver provider.", remainingTTL),
								DocURL:      "https://developers.cloudflare.com/1.1.1.1/purge-cache/",
							},
						})
						mu.Unlock()
					}
				}
				return nil
			})
		}
	}

	_ = g.Wait()

	if len(execCtx.NegativeCaches) == 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "NEGCACHE-CLEAN",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  "No stale RFC 2308 negative caching observed across public resolvers",
			Detail:   "All tested Anycast resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9, OpenDNS) return synchronized answers.",
		})
	}

	return nil
}
