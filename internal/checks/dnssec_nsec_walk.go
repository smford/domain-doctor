package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type NSECWalkCheck struct{}

func (c *NSECWalkCheck) Name() string     { return "dnssec_nsec_walk" }
func (c *NSECWalkCheck) Category() string { return "Security" }

func (c *NSECWalkCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	// Only applicable if zone is DNSSEC-signed
	hasDNSSEC := len(execCtx.Records["DNSKEY"]) > 0 || len(execCtx.Records["DS"]) > 0
	if !hasDNSSEC {
		return nil
	}

	probeServer := "1.1.1.1:53"
	if len(execCtx.Nameservers) > 0 {
		probeServer = execCtx.Nameservers[0]
	}

	nonExistentDomain := fmt.Sprintf("_walk_probe_%d.%s", time.Now().UnixNano(), execCtx.Domain)
	msg, _, err := execCtx.DNSProber.QueryWithDO(probeServer, nonExistentDomain, dns.TypeA)
	if err != nil || msg == nil {
		return nil
	}

	hasNSEC := false
	hasNSEC3 := false

	for _, nsRR := range msg.Ns {
		if nsRR.Header().Rrtype == dns.TypeNSEC {
			hasNSEC = true
		} else if nsRR.Header().Rrtype == dns.TypeNSEC3 {
			hasNSEC3 = true
		}
	}

	if hasNSEC && !hasNSEC3 {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNSSEC-ZONE-WALKABLE-NSEC",
			Category: c.Category(),
			Severity: engine.SeverityWarning,
			Summary:  "DNSSEC zone uses plain NSEC (RFC 4034), exposing all zone hostnames to zone walking",
			Detail:   "Plain NSEC records advertise the exact alphabetical next domain name in NXDOMAIN responses, allowing automated enumeration of all private and internal subdomains in the zone.",
			Remediation: &engine.Remediation{
				Title:       "Migrate to Hashed NSEC3 or Minimal NSEC",
				Explanation: "Enable NSEC3 (RFC 5155) with cryptographic hashing or dynamic minimal NSEC (RFC 4470 'white lies') in your DNS provider / BIND configuration.",
				DocURL:      "https://datatracker.ietf.org/doc/html/rfc5155",
			},
		})
	} else if hasNSEC3 {
		execCtx.AddFinding(engine.Finding{
			ID:       "DNSSEC-NSEC3-PROTECTED",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  "DNSSEC zone uses hashed NSEC3 (RFC 5155) preventing cleartext zone enumeration",
			Detail:   "Negative denial-of-existence responses use salted cryptographic hashes, protecting against zone-walking discovery.",
		})
	}

	return nil
}
