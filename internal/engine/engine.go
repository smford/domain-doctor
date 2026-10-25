package engine

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"github.com/smford/domain-doctor/internal/prober"
)

type Check interface {
	Name() string
	Category() string
	Run(ctx context.Context, execCtx *ExecutionContext) error
}

type ExecutionContext struct {
	Domain      string
	Nameservers []string
	SOA         *ZoneSOA

	DNSProber *prober.DefaultDNSProber
	TCPProber *prober.TCPProber

	mu             sync.Mutex
	Records        map[string][]string
	Findings       []Finding
	NegativeCaches []NegativeCacheStatus
}

func NewExecutionContext(domain string, dnsTimeout time.Duration) *ExecutionContext {
	cleanDomain := strings.TrimSuffix(strings.TrimSpace(domain), ".")
	return &ExecutionContext{
		Domain:         cleanDomain,
		Records:        make(map[string][]string),
		Findings:       make([]Finding, 0),
		NegativeCaches: make([]NegativeCacheStatus, 0),
		DNSProber:      prober.NewDefaultDNSProber(dnsTimeout),
		TCPProber:      prober.NewTCPProber(dnsTimeout),
	}
}

func (c *ExecutionContext) AddFinding(f Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Findings = append(c.Findings, f)
}

func (c *ExecutionContext) AddNegativeCache(s NegativeCacheStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.NegativeCaches = append(c.NegativeCaches, s)
}

func (c *ExecutionContext) AddRecord(rtype string, rr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Records[rtype] = append(c.Records[rtype], rr)
}

func (c *ExecutionContext) SetSOA(soa *ZoneSOA) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.SOA = soa
}

type Engine struct {
	checks      []Check
	workerLimit int
	timeout     time.Duration
}

func NewEngine(timeout time.Duration, workerLimit int) *Engine {
	if workerLimit <= 0 {
		workerLimit = 10
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Engine{
		checks:      make([]Check, 0),
		workerLimit: workerLimit,
		timeout:     timeout,
	}
}

func (e *Engine) Register(c Check) {
	e.checks = append(e.checks, c)
}

func (e *Engine) Run(parentCtx context.Context, domain string, customResolver string) (*DiagnosticReport, error) {
	startTime := time.Now()
	ctx, cancel := context.WithTimeout(parentCtx, e.timeout)
	defer cancel()

	execCtx := NewExecutionContext(domain, 4*time.Second)

	// Step 1: Discover Authoritative Nameservers and basic SOA
	e.bootstrapDomain(ctx, execCtx, customResolver)

	// Step 2: Concurrently run all registered checks
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(e.workerLimit)

	for _, check := range e.checks {
		chk := check
		g.Go(func() error {
			if gCtx.Err() != nil {
				return gCtx.Err()
			}
			// Catch panics in individual checks to ensure resilient isolation
			defer func() {
				if r := recover(); r != nil {
					execCtx.AddFinding(Finding{
						ID:       fmt.Sprintf("%s-PANIC", chk.Name()),
						Category: chk.Category(),
						Severity: SeverityWarning,
						Summary:  fmt.Sprintf("Internal check error in %s", chk.Name()),
						Detail:   fmt.Sprintf("Check recovered from panic: %v", r),
					})
				}
			}()

			if err := chk.Run(gCtx, execCtx); err != nil {
				// Resilient error isolation: individual network failures add informational/warning findings
				execCtx.AddFinding(Finding{
					ID:       fmt.Sprintf("%s-EXEC-ERR", chk.Name()),
					Category: chk.Category(),
					Severity: SeverityInfo,
					Summary:  fmt.Sprintf("Check %s incomplete due to network condition", chk.Name()),
					Detail:   err.Error(),
				})
			}
			return nil
		})
	}

	_ = g.Wait()

	report := &DiagnosticReport{
		Domain:         execCtx.Domain,
		Timestamp:      startTime,
		Duration:       time.Since(startTime),
		Nameservers:    execCtx.Nameservers,
		Findings:       execCtx.Findings,
		NegativeCaches: execCtx.NegativeCaches,
		Records:        execCtx.Records,
	}

	return report, nil
}

func (e *Engine) bootstrapDomain(ctx context.Context, execCtx *ExecutionContext, customResolver string) {
	resolver := "1.1.1.1:53"
	if customResolver != "" {
		resolver = customResolver
	}

	// Discover NS
	msg, _, err := execCtx.DNSProber.QueryRecursive(resolver, execCtx.Domain, dns.TypeNS)
	if err == nil && msg != nil && len(msg.Answer) > 0 {
		for _, ans := range msg.Answer {
			if ns, ok := ans.(*dns.NS); ok {
				nsTarget := strings.TrimSuffix(ns.Ns, ".")
				execCtx.Nameservers = append(execCtx.Nameservers, nsTarget)
				execCtx.AddRecord("NS", nsTarget)
			}
		}
	}

	// Discover SOA
	soaMsg, _, soaErr := execCtx.DNSProber.QueryRecursive(resolver, execCtx.Domain, dns.TypeSOA)
	if soaErr == nil && soaMsg != nil && len(soaMsg.Answer) > 0 {
		for _, ans := range soaMsg.Answer {
			if soa, ok := ans.(*dns.SOA); ok {
				zoneSOA := &ZoneSOA{
					Mname:   strings.TrimSuffix(soa.Ns, "."),
					Rname:   strings.TrimSuffix(soa.Mbox, "."),
					Serial:  soa.Serial,
					Refresh: soa.Refresh,
					Retry:   soa.Retry,
					Expire:  soa.Expire,
					Minttl:  soa.Minttl,
					TTL:     soa.Hdr.Ttl,
				}
				execCtx.SetSOA(zoneSOA)
				execCtx.AddRecord("SOA", fmt.Sprintf("%s %s %d %d %d %d %d",
					zoneSOA.Mname, zoneSOA.Rname, zoneSOA.Serial, zoneSOA.Refresh, zoneSOA.Retry, zoneSOA.Expire, zoneSOA.Minttl))
			}
		}
	}

	// Fallback NS via host resolver if recursive query was empty
	if len(execCtx.Nameservers) == 0 {
		nss, err := net.LookupNS(execCtx.Domain)
		if err == nil {
			for _, ns := range nss {
				nsTarget := strings.TrimSuffix(ns.Host, ".")
				execCtx.Nameservers = append(execCtx.Nameservers, nsTarget)
				execCtx.AddRecord("NS", nsTarget)
			}
		}
	}
}
