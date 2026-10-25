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

type CTLogCheck struct{}

func (c *CTLogCheck) ID() string       { return "DD-THR-001" }
func (c *CTLogCheck) Name() string     { return "threat_ct_logs" }
func (c *CTLogCheck) Category() string { return "Threat" }

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

func (c *CTLogCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	ctURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", execCtx.Domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ctURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "domain-doctor-diagnostic/1.0")

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		execCtx.AddFinding(engine.Finding{
			ID:       "CT-LOGS-TIMEOUT",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  "Certificate Transparency log query timed out or unavailable",
			Detail:   fmt.Sprintf("crt.sh public endpoint did not respond: %v", err),
		})
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var entries []crtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil
	}

	subdomains := make(map[string]bool)
	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			clean := strings.ToLower(strings.TrimSpace(name))
			clean = strings.TrimPrefix(clean, "*.")
			if strings.HasSuffix(clean, "."+execCtx.Domain) && clean != execCtx.Domain {
				subdomains[clean] = true
			}
		}
	}

	if len(subdomains) > 0 {
		sample := make([]string, 0, 5)
		for sub := range subdomains {
			sample = append(sample, sub)
			if len(sample) >= 5 {
				break
			}
		}

		execCtx.AddFinding(engine.Finding{
			ID:       "CT-LOGS-DISCOVERY",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  fmt.Sprintf("Discovered %d subdomains via public Certificate Transparency logs", len(subdomains)),
			Detail:   fmt.Sprintf("Sample subdomains: %s", strings.Join(sample, ", ")),
		})
	}

	return nil
}
