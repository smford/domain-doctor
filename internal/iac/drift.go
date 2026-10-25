package iac

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/smford/domain-doctor/internal/engine"
)

type tfState struct {
	Resources []struct {
		Type      string `json:"type"`
		Name      string `json:"name"`
		Instances []struct {
			Attributes map[string]interface{} `json:"attributes"`
		} `json:"instances"`
	} `json:"resources"`
}

type DriftFinding struct {
	ResourceName string `json:"resource_name"`
	RecordType   string `json:"record_type"`
	StateRecords string `json:"state_records"`
	LiveRecords  string `json:"live_records"`
	Status       string `json:"status"` // "MATCH", "DRIFT", "MISSING_IN_LIVE"
}

func AuditDrift(tfStatePath string, liveReport *engine.DiagnosticReport) ([]DriftFinding, error) {
	data, err := os.ReadFile(tfStatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read tfstate file: %w", err)
	}

	var state tfState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse tfstate json: %w", err)
	}

	findings := make([]DriftFinding, 0)

	for _, res := range state.Resources {
		if res.Type == "aws_route53_record" || res.Type == "cloudflare_record" {
			for _, inst := range res.Instances {
				name, _ := inst.Attributes["name"].(string)
				rtype, _ := inst.Attributes["type"].(string)

				if strings.Contains(name, liveReport.Domain) {
					stateRecords := ""
					if recs, ok := inst.Attributes["records"].([]interface{}); ok {
						parts := make([]string, 0, len(recs))
						for _, r := range recs {
							parts = append(parts, fmt.Sprint(r))
						}
						stateRecords = strings.Join(parts, ", ")
					} else if val, ok := inst.Attributes["value"].(string); ok {
						stateRecords = val
					}

					liveRecords := strings.Join(liveReport.Records[rtype], ", ")
					status := "MATCH"
					if liveRecords == "" {
						status = "MISSING_IN_LIVE"
					} else if stateRecords != liveRecords {
						status = "DRIFT"
					}

					findings = append(findings, DriftFinding{
						ResourceName: res.Name,
						RecordType:   rtype,
						StateRecords: stateRecords,
						LiveRecords:  liveRecords,
						Status:       status,
					})
				}
			}
		}
	}

	return findings, nil
}
