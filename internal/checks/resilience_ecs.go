package checks

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type ECSGeoCheck struct{}

func (c *ECSGeoCheck) ID() string       { return "DD-RES-002" }
func (c *ECSGeoCheck) Name() string     { return "resilience_ecs" }
func (c *ECSGeoCheck) Category() string { return "Resilience" }

func (c *ECSGeoCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	regions := map[string]net.IP{
		"North America": net.ParseIP("8.8.8.0"),
		"Europe":        net.ParseIP("185.199.108.0"),
		"Asia-Pacific":  net.ParseIP("203.116.1.0"),
	}

	geoAnswers := make(map[string]string) // Region -> IP answers

	for region, clientIP := range regions {
		msg, _, err := execCtx.DNSProber.QueryWithSubnet("8.8.8.8:53", execCtx.Domain, dns.TypeA, clientIP)
		if err == nil && msg != nil && len(msg.Answer) > 0 {
			ips := make([]string, 0)
			for _, ans := range msg.Answer {
				if a, ok := ans.(*dns.A); ok {
					ips = append(ips, a.A.String())
				}
			}
			if len(ips) > 0 {
				geoAnswers[region] = strings.Join(ips, ",")
			}
		}
	}

	if len(geoAnswers) >= 2 {
		isSplitBrain := false
		firstAns := ""
		for _, ans := range geoAnswers {
			if firstAns == "" {
				firstAns = ans
			} else if firstAns != ans {
				isSplitBrain = true
				break
			}
		}

		if isSplitBrain {
			execCtx.AddFinding(engine.Finding{
				ID:       "ECS-GEO-STEERING-ACTIVE",
				Category: c.Category(),
				Severity: engine.SeverityInfo,
				Summary:  "EDNS Client Subnet (ECS) Geo-Steering active across global regions",
				Detail:   fmt.Sprintf("DNS answers dynamically adapt based on client geography: %v", geoAnswers),
			})
		} else {
			execCtx.AddFinding(engine.Finding{
				ID:       "ECS-ANYCAST-GLOBAL",
				Category: c.Category(),
				Severity: engine.SeverityPass,
				Summary:  "Global Anycast / Uniform A record resolution verified",
				Detail:   "All queried geographic regions receive identical IP routing targets.",
			})
		}
	}

	return nil
}
