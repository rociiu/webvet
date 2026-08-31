package report

import (
	"encoding/json"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

type RuleInfo struct {
	ID          string
	Name        string
	Description string
	CWE         string
}

func WriteSARIF(w io.Writer, findings []Finding, metadata []RuleInfo, version string) error {
	sort.Slice(metadata, func(i, j int) bool { return metadata[i].ID < metadata[j].ID })
	indices := map[string]int{}
	rules := make([]sarifRule, 0, len(metadata))
	for i, m := range metadata {
		indices[m.ID] = i
		properties := map[string]any{}
		if m.CWE != "" {
			properties["tags"] = []string{"security", m.CWE}
		}
		rules = append(rules, sarifRule{ID: m.ID, Name: m.Name, ShortDescription: sarifMessage{Text: m.Description}, HelpURI: "https://github.com/rociiu/webvet/blob/main/docs/rules/" + m.ID + ".md", Properties: properties})
	}
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		result := sarifResult{RuleID: f.RuleID, RuleIndex: indices[f.RuleID], Level: sarifLevel(f.Severity), Message: sarifMessage{Text: f.Message + " " + f.Explanation + " Remediation: " + f.Remediation}}
		result.Locations = []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: artifactURI(f.Filename)}, Region: sarifRegion{StartLine: f.Line, StartColumn: f.Column}}}}
		results = append(results, result)
	}
	doc := sarifLog{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "webvet", Version: version, InformationURI: "https://github.com/rociiu/webvet", Rules: rules}}, Results: results}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func artifactURI(filename string) string {
	rel, err := filepath.Rel(".", filename)
	if err == nil && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		filename = rel
	}
	return filepath.ToSlash(filename)
}

func sarifLevel(s Severity) string {
	if s >= High {
		return "error"
	}
	if s == Medium {
		return "warning"
	}
	return "note"
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	HelpURI          string         `json:"helpUri"`
	Properties       map[string]any `json:"properties,omitempty"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}
type sarifArtifactLocation struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}
