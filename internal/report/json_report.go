package report

import (
	"time"

	"github.com/Al-Gharbi/blocksec-auditor/internal/checks"
)

type JSONReport struct {
	Timestamp string              `json:"timestamp"`
	Results   []checks.CheckResult `json:"results"`
	Summary   map[checks.RiskLevel]int `json:"summary"`
}

func NewJSONReport(results []checks.CheckResult) JSONReport {
	summary := map[checks.RiskLevel]int{}
	for _, r := range results {
		if !r.Passed {
			summary[r.Risk]++
		}
	}
	return JSONReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Results:   results,
		Summary:   summary,
	}
}
