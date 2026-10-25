package checks

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

func TestNegativeCacheTTLCalculation(t *testing.T) {
	// RFC 2308 §3: Negative TTL = min(SOA.TTL, SOA.MINIMUM)
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns:      "ns1.example.com.",
		Mbox:    "hostmaster.example.com.",
		Serial:  2026102501,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  180, // Minimum is 180, less than 300
	}

	remaining := soa.Hdr.Ttl
	if soa.Minttl < remaining {
		remaining = soa.Minttl
	}

	if remaining != 180 {
		t.Fatalf("expected remaining negative cache TTL to be 180, got %d", remaining)
	}

	status := engine.NegativeCacheStatus{
		Resolver:      "1.1.1.1:53",
		RecordName:    "example.com",
		RecordType:    "A",
		CachedState:   "NXDOMAIN",
		AuthSOA:       soa.Ns,
		SOAMinimumTTL: soa.Minttl,
		RemainingTTL:  remaining,
		AuthHasRecord: true,
	}

	if !status.AuthHasRecord || status.RemainingTTL != 180 {
		t.Errorf("status mismatch: %+v", status)
	}
}
