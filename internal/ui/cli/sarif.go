package cli

import (
	"encoding/json"
	"fmt"
	"strings"

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
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules,omitempty"`
}

type SarifRule struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	ShortDescription SarifMultiformatText `json:"shortDescription"`
	FullDescription  SarifMultiformatText `json:"fullDescription"`
	Help             SarifHelp            `json:"help,omitempty"`
	HelpURI          string               `json:"helpUri,omitempty"`
}

type SarifMultiformatText struct {
	Text string `json:"text"`
}

type SarifHelp struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

type SarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SarifMessage    `json:"message"`
	Locations []SarifLocation `json:"locations,omitempty"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

func GenerateSARIF(report *engine.DiagnosticReport, version string) (string, error) {
	rulesMap := make(map[string]SarifRule)
	results := make([]SarifResult, 0)

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

		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = f.ID
		}

		if _, exists := rulesMap[ruleID]; !exists {
			helpMD := f.Detail
			helpURI := "https://stephenford.org/domain-doctor/"
			if f.Remediation != nil {
				helpMD = fmt.Sprintf("### %s\n\n%s\n\n**Suggested Action:**\n```\n%s\n```\n\n[Reference](%s)",
					f.Remediation.Title, f.Remediation.Explanation, f.Remediation.Suggested, f.Remediation.DocURL)
				if f.Remediation.DocURL != "" {
					helpURI = f.Remediation.DocURL
				}
			}

			rulesMap[ruleID] = SarifRule{
				ID:   ruleID,
				Name: strings.ReplaceAll(f.ID, "-", "_"),
				ShortDescription: SarifMultiformatText{
					Text: f.Summary,
				},
				FullDescription: SarifMultiformatText{
					Text: f.Detail,
				},
				Help: SarifHelp{
					Text:     f.Detail,
					Markdown: helpMD,
				},
				HelpURI: helpURI,
			}
		}

		results = append(results, SarifResult{
			RuleID: ruleID,
			Level:  level,
			Message: SarifMessage{
				Text: f.Summary + ": " + f.Detail,
			},
			Locations: []SarifLocation{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{
							URI: fmt.Sprintf("dns:%s", report.Domain),
						},
					},
				},
			},
		})
	}

	rulesList := make([]SarifRule, 0, len(rulesMap))
	for _, r := range rulesMap {
		rulesList = append(rulesList, r)
	}

	doc := SarifReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "domain-doctor",
						Version:        version,
						InformationURI: "https://github.com/smford/domain-doctor",
						Rules:          rulesList,
					},
				},
				Results: results,
			},
		},
	}

	bytes, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
