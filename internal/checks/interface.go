package checks

import (
	"context"
	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
)

type RiskLevel string

const (
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

type CheckResult struct {
	Name        string      `json:"name"`
	Risk        RiskLevel   `json:"risk"`
	Description string      `json:"description"`
	Remediation string      `json:"remediation"`
	Passed      bool        `json:"passed"`
	Details     interface{} `json:"details"`
}

type Check interface {
	Name() string
	Description() string
	RiskLevel() RiskLevel
	Run(ctx context.Context, client *scanner.Client) (CheckResult, error)
}
