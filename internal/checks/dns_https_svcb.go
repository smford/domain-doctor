package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type HTTPSSVCBCheck struct{}

func (c *HTTPSSVCBCheck) ID() string       { return "DD-DNS-004" }
func (c *HTTPSSVCBCheck) Name() string     { return "dns_https_svcb" }
func (c *HTTPSSVCBCheck) Category() string { return "DNS" }

func (c *HTTPSSVCBCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	hosts := []string{execCtx.Domain, "www." + execCtx.Domain}
	discovered := make([]string, 0)
	hasH3 := false
	hasECH := false

	for _, host := range hosts {
		msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", host, dns.TypeHTTPS)
		if err == nil && msg != nil {
			for _, ans := range msg.Answer {
				if httpsRR, ok := ans.(*dns.HTTPS); ok {
					str := httpsRR.String()
					execCtx.AddRecord("HTTPS", fmt.Sprintf("%s: %s", host, str))
					discovered = append(discovered, fmt.Sprintf("%s (pri: %d)", host, httpsRR.Priority))
					for _, kv := range httpsRR.Value {
						if kv.Key() == dns.SVCB_ALPN && strings.Contains(kv.String(), "h3") {
							hasH3 = true
						}
						if kv.Key() == dns.SVCB_ECHCONFIG {
							hasECH = true
						}
					}
				}
			}
		}
	}

	if len(discovered) > 0 {
		h3Status := "disabled"
		if hasH3 {
			h3Status = "enabled (HTTP/3 advertised)"
		}
		echStatus := "disabled"
		if hasECH {
			echStatus = "enabled (Encrypted Client Hello)"
		}

		execCtx.AddFinding(engine.Finding{
			ID:       "HTTPS-SVCB-CONFIGURED",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  fmt.Sprintf("HTTPS Service Binding (RFC 9460) configured on [%s]", strings.Join(discovered, ", ")),
			Detail:   fmt.Sprintf("Direct ALPN: %s; ECH: %s. Enables zero-RTT HTTP/3 connection establishment and SNI encryption in modern browsers.", h3Status, echStatus),
		})
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "HTTPS-SVCB-NOT-PUBLISHED",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  "HTTPS Service Binding (Type 65, RFC 9460) records not published",
			Detail:   "Publishing Type 65 HTTPS records allows browsers to initiate HTTP/3 (QUIC) connections on the initial request and encrypt TLS SNI headers via ECH.",
			Remediation: &engine.Remediation{
				Title:       "Publish Type 65 HTTPS Record",
				RecordType:  "HTTPS",
				Suggested:   fmt.Sprintf("%s. IN HTTPS 1 . alpn=\"h3,h2\"", execCtx.Domain),
				Explanation: "Advertise supported application protocols and direct connection parameters at the DNS layer.",
				DocURL:      "https://datatracker.ietf.org/doc/html/rfc9460",
			},
		})
	}

	return nil
}
