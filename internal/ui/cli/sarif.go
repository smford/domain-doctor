package cli

import (
	"encoding/json"

	"github.com/smford/domain-doctor/internal/engine"
)

type SarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
}

type SarifResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message SarifMessage `json:"message"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

func GenerateSARIF(report *engine.DiagnosticReport, version string) (string, error) {
	run := SarifRun{
		Tool: SarifTool{
			Driver: SarifDriver{
				Name:           "domain-doctor",
				Version:        version,
				InformationURI: "https://github.com/smford/domain-doctor",
			},
		},
		Results: make([]SarifResult, 0),
	}

	for _, f := range report.Findings {
		level := "note"
		switch f.Severity {
		case engine.SeverityCritical:
			level = "error"
		case engine.SeverityWarning:
			level = "warning"
		case engine.SeverityInfo:
			level = "note"
		default:
			continue
		}

		run.Results = append(run.Results, SarifResult{
			RuleID: f.ID,
			Level:  level,
			Message: SarifMessage{
				Text: f.Summary + ": " + f.Detail,
			},
		})
	}

	doc := SarifReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []SarifRun{run},
	}

	bytes, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
