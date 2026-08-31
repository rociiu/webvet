package report

import (
	"encoding/json"
	"io"
)

func WriteJSON(w io.Writer, findings []Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Findings []Finding `json:"findings"`
		Count    int       `json:"count"`
	}{findings, len(findings)})
}
