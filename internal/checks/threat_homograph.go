package checks

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type HomographCheck struct{}

func (c *HomographCheck) Name() string     { return "threat_homograph" }
func (c *HomographCheck) Category() string { return "Threat" }

func (c *HomographCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	parts := strings.Split(execCtx.Domain, ".")
	if len(parts) < 2 {
		return nil
	}

	name := parts[0]
	tld := strings.Join(parts[1:], ".")

	// Generate sample bit-flip / typo variations (bounded to first 6 to keep runtime fast and non-invasive)
	variations := make([]string, 0)

	// Single character omissions and transpositions
	if len(name) > 3 {
		variations = append(variations, fmt.Sprintf("%s.%s", name[1:], tld))
		variations = append(variations, fmt.Sprintf("%s%c%c%s.%s", name[:1], name[2], name[1], name[3:], tld))
	}

	// Bit flips
	nameBytes := []byte(name)
	for i := 0; i < len(nameBytes) && len(variations) < 6; i++ {
		for bit := 0; bit < 8; bit++ {
			flipped := make([]byte, len(nameBytes))
			copy(flipped, nameBytes)
			flipped[i] ^= (1 << bit)

			char := flipped[i]
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
				candidate := fmt.Sprintf("%s.%s", string(flipped), tld)
				if candidate != execCtx.Domain {
					variations = append(variations, candidate)
					if len(variations) >= 6 {
						break
					}
				}
			}
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	registeredLookalikes := make([]string, 0)

	for _, v := range variations {
		domainVar := v
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", domainVar, dns.TypeNS)
			if err == nil && msg != nil && len(msg.Answer) > 0 {
				mu.Lock()
				registeredLookalikes = append(registeredLookalikes, domainVar)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(registeredLookalikes) > 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "THREAT-LOOKALIKE-DOMAINS-REGISTERED",
			Category: c.Category(),
			Severity: engine.SeverityWarning,
			Summary:  fmt.Sprintf("Discovered %d active lookalike / bitsquatting domain(s) with registered nameservers", len(registeredLookalikes)),
			Detail:   fmt.Sprintf("Registered variations: [%s]. These domains may be used for executive impersonation, phishing campaigns, or opportunistic bit-flip traffic interception.", strings.Join(registeredLookalikes, ", ")),
			Remediation: &engine.Remediation{
				Title:       "Monitor or Defensively Register Brand Lookalikes",
				Explanation: "Consider defensive registration or brand protection monitoring via registrar domain blocks.",
			},
		})
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "THREAT-LOOKALIKE-CLEAN",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  "Sampled bitsquatting and lookalike domains are unregistered",
			Detail:   fmt.Sprintf("Probed %d permutations without detecting active DNS authority.", len(variations)),
		})
	}

	return nil
}
