package report

import (
	"encoding/json"
	"fmt"
	"io"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool              `json:"tool"`
	Results    []sarifResult          `json:"results"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	ShortDescription     sarifText              `json:"shortDescription"`
	FullDescription      sarifText              `json:"fullDescription,omitempty"`
	DefaultConfiguration sarifDefaultConfig     `json:"defaultConfiguration"`
	HelpURI              string                 `json:"helpUri,omitempty"`
	Help                 *sarifText             `json:"help,omitempty"`
	Properties           map[string]interface{} `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical  `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifLogical struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

func severityToLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	case SeverityLow, SeverityInfo:
		return "note"
	}
	return "none"
}

func severityToScore(s Severity) string {
	switch s {
	case SeverityCritical:
		return "9.0"
	case SeverityHigh:
		return "7.0"
	case SeverityMedium:
		return "5.0"
	case SeverityLow:
		return "3.0"
	case SeverityInfo:
		return "1.0"
	}
	return "0.0"
}

// WriteSARIF sérialise au format SARIF 2.1.0.
func WriteSARIF(w io.Writer, r ScanResult, toolURI string) error {
	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
	}

	rulesMap := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(r.Findings))

	for _, f := range r.Findings {
		if f.Status != "FAILED" {
			continue
		}

		if _, ok := rulesMap[f.RuleID]; !ok {
			rulesMap[f.RuleID] = sarifRule{
				ID:                   f.RuleID,
				Name:                 f.RuleID,
				ShortDescription:     sarifText{Text: f.RuleTitle},
				FullDescription:      sarifText{Text: f.Description},
				DefaultConfiguration: sarifDefaultConfig{Level: severityToLevel(f.Severity)},
				HelpURI:              fmt.Sprintf("%s/rules/%s/%s", toolURI, f.Category, f.RuleID),
				Help:                 &sarifText{Text: f.Remediation},
				Properties: map[string]interface{}{
					"tags":              []string{string(f.Category)},
					"precision":         "high",
					"problem.severity":  severityToLevel(f.Severity),
					"security-severity": severityToScore(f.Severity),
				},
			}
		}

		uri := "live"
		if f.FilePath != "" {
			uri = f.FilePath
		}
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   severityToLevel(f.Severity),
			Message: sarifText{Text: f.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}},
				LogicalLocations: []sarifLogical{{Name: f.ResourceAddress, Kind: "resource"}},
			}},
		})
	}

	rules := make([]sarifRule, 0, len(rulesMap))
	for _, rl := range rulesMap {
		rules = append(rules, rl)
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "osc-policy",
			Version:        r.ToolVersion,
			InformationURI: toolURI,
			Rules:          rules,
		}},
		Results: results,
	}
	if r.Score != nil {
		svcs := make([]map[string]interface{}, 0, len(r.Score.Services))
		for _, svc := range r.Score.Services {
			svcs = append(svcs, map[string]interface{}{
				"service":      svc.Service,
				"score":        svc.Score,
				"grade":        string(svc.Grade),
				"total_fail":   svc.TotalFail,
				"total_checks": svc.TotalChecks,
			})
		}
		run.Properties = map[string]interface{}{
			"osc_policy_score": map[string]interface{}{
				"score":                r.Score.Score,
				"grade":                string(r.Score.Grade),
				"label":                r.Score.Label,
				"critical_cap_applied": r.Score.CriticalCapApplied,
				"total_fail":           r.Score.TotalFail,
				"total_pass":           r.Score.TotalPass,
				"total_checks":         r.Score.TotalChecks,
				"services":             svcs,
			},
		}
	}
	log.Runs = []sarifRun{run}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
