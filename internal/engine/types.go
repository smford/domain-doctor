package engine

import (
	"time"
)

type Severity string

const (
	SeverityPass     Severity = "PASS"
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARN"
	SeverityCritical Severity = "CRIT"
)

type Remediation struct {
	Title       string `json:"title"`
	RecordType  string `json:"record_type,omitempty"`
	Suggested   string `json:"suggested,omitempty"`
	Explanation string `json:"explanation"`
	DocURL      string `json:"doc_url,omitempty"`
}

type Finding struct {
	RuleID      string       `json:"rule_id,omitempty"`
	ID          string       `json:"id"`
	Category    string       `json:"category"` // "DNS", "Mail", "Security", "Resilience", "Threat", "Registration", "NegativeCache"
	Severity    Severity     `json:"severity"`
	Summary     string       `json:"summary"`
	Detail      string       `json:"detail"`
	Remediation *Remediation `json:"remediation,omitempty"`
}

type NegativeCacheStatus struct {
	Resolver      string `json:"resolver"` // e.g., "1.1.1.1:53"
	RecordName    string `json:"record_name"`
	RecordType    string `json:"record_type"`
	CachedState   string `json:"cached_state"`    // "NXDOMAIN" or "NODATA"
	AuthSOA       string `json:"auth_soa"`        // Primary master reported in SOA
	SOAMinimumTTL uint32 `json:"soa_minimum_ttl"` // RFC 2308 negative cache TTL
	RemainingTTL  uint32 `json:"remaining_ttl"`   // Seconds remaining before eviction
	AuthHasRecord bool   `json:"auth_has_record"` // True if authoritative NS already serves record
}

type ZoneSOA struct {
	Mname   string `json:"mname"`
	Rname   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minttl  uint32 `json:"minttl"`
	TTL     uint32 `json:"ttl"`
}

type ZoneSnapshot struct {
	Domain    string              `json:"domain"`
	Timestamp time.Time           `json:"timestamp"`
	SOA       *ZoneSOA            `json:"soa,omitempty"`
	Records   map[string][]string `json:"records"` // Type -> list of stringified RRs
	Findings  []Finding           `json:"findings"`
}

type DiagnosticReport struct {
	Domain         string                `json:"domain"`
	Timestamp      time.Time             `json:"timestamp"`
	Duration       time.Duration         `json:"duration"`
	Nameservers    []string              `json:"nameservers"`
	Findings       []Finding             `json:"findings"`
	NegativeCaches []NegativeCacheStatus `json:"negative_caches,omitempty"`
	Records        map[string][]string   `json:"records,omitempty"`
}
