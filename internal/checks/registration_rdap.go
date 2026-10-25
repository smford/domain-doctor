package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/smford/domain-doctor/internal/engine"
)

type RDAPCheck struct{}

func (c *RDAPCheck) ID() string       { return "DD-REG-002" }
func (c *RDAPCheck) Name() string     { return "registration_rdap" }
func (c *RDAPCheck) Category() string { return "Registration" }

type rdapEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type rdapResponse struct {
	Status []string    `json:"status"`
	Events []rdapEvent `json:"events"`
}

func (c *RDAPCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	rdapURL := fmt.Sprintf("https://rdap.org/domain/%s", execCtx.Domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rdapURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "domain-doctor-diagnostic/1.0")
	req.Header.Set("Accept", "application/rdap+json, application/json")

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		execCtx.AddFinding(engine.Finding{
			ID:       "RDAP-LOOKUP-TIMEOUT",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  "RDAP registration lookup timed out or service unavailable",
			Detail:   fmt.Sprintf("rdap.org query failed: %v", err),
		})
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var data rdapResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}

	// 1. Check expiration event
	for _, ev := range data.Events {
		if ev.EventAction == "expiration" {
			t, parseErr := time.Parse(time.RFC3339, ev.EventDate)
			if parseErr == nil {
				daysUntil := int(time.Until(t).Hours() / 24)
				if daysUntil < 7 {
					execCtx.AddFinding(engine.Finding{
						ID:       "REG-EXPIRING-IMMINENT",
						Category: c.Category(),
						Severity: engine.SeverityCritical,
						Summary:  fmt.Sprintf("Domain registration expires in %d days (%s)!", daysUntil, t.Format("2006-01-02")),
						Detail:   "Urgent: Renew domain with your registrar immediately to prevent zone de-delegation and DNS outage.",
					})
				} else if daysUntil < 30 {
					execCtx.AddFinding(engine.Finding{
						ID:       "REG-EXPIRING-SOON",
						Category: c.Category(),
						Severity: engine.SeverityWarning,
						Summary:  fmt.Sprintf("Domain registration expires within %d days (%s)", daysUntil, t.Format("2006-01-02")),
						Detail:   "Ensure auto-renewal is enabled and payment methods are up to date.",
					})
				} else {
					execCtx.AddFinding(engine.Finding{
						ID:       "REG-EXPIRATION-HEALTHY",
						Category: c.Category(),
						Severity: engine.SeverityPass,
						Summary:  fmt.Sprintf("Domain registration active until %s (%d days remaining)", t.Format("2006-01-02"), daysUntil),
						Detail:   "Registration expiry is safely beyond the 30-day renewal threshold.",
					})
				}
			}
			break
		}
	}

	// 2. Check transfer locks
	hasTransferLock := false
	for _, st := range data.Status {
		lower := strings.ToLower(st)
		if strings.Contains(lower, "transferprohibited") || strings.Contains(lower, "locked") {
			hasTransferLock = true
			break
		}
	}

	if hasTransferLock {
		execCtx.AddFinding(engine.Finding{
			ID:       "REG-TRANSFER-LOCK-ACTIVE",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  "Domain Transfer Lock (clientTransferProhibited / serverTransferProhibited) active",
			Detail:   "Registrar lock prevents unauthorized or fraudulent domain transfer requests.",
		})
	} else if len(data.Status) > 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "REG-TRANSFER-LOCK-MISSING",
			Category: c.Category(),
			Severity: engine.SeverityWarning,
			Summary:  "Domain Transfer Lock is disabled at registrar",
			Detail:   "Without transfer locking, your domain is vulnerable to social engineering registrar hijacks.",
			Remediation: &engine.Remediation{
				Title:       "Enable Domain Transfer Lock (Registrar Lock)",
				Explanation: "Log into your domain registrar dashboard and toggle on the Transfer Lock feature.",
			},
		})
	}

	return nil
}
