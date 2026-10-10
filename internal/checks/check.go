// Package checks implements the individual security checks.
//
// Every check is read-only: it only sends calls that cannot change node state
// (no account creation, no transaction submission, no admin mutation).
package checks

import (
	"context"
	"sort"
	"strings"

	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
)

// RiskLevel is the severity of a finding.
type RiskLevel string

const (
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// Rank orders risk levels (higher is more severe). Unknown values rank 0.
func (r RiskLevel) Rank() int {
	switch r {
	case RiskLow:
		return 1
	case RiskMedium:
		return 2
	case RiskHigh:
		return 3
	case RiskCritical:
		return 4
	}
	return 0
}

// ParseRisk converts a user-supplied string to a RiskLevel.
func ParseRisk(s string) (RiskLevel, bool) {
	r := RiskLevel(strings.ToUpper(strings.TrimSpace(s)))
	return r, r.Rank() > 0
}

// Status is the outcome of a check. Only PASS means "checked and fine".
// ERROR (could not determine) and SKIPPED (not applicable here) are never
// counted as a pass: an unreachable node must not look like a clean node.
type Status string

const (
	StatusPass    Status = "PASS"
	StatusFail    Status = "FAIL"
	StatusError   Status = "ERROR"
	StatusSkipped Status = "SKIPPED"
)

// CheckResult is what a check reports.
type CheckResult struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Risk        RiskLevel   `json:"risk"`
	Status      Status      `json:"status"`
	Passed      bool        `json:"passed"` // true only when Status == PASS
	Description string      `json:"description"`
	Remediation string      `json:"remediation,omitempty"`
	Details     interface{} `json:"details,omitempty"`
}

// Options are the tunables shared by the checks.
type Options struct {
	MinPeers int // net_peerCount below this fails the peer check
}

// DefaultOptions returns the defaults.
func DefaultOptions() Options { return Options{MinPeers: 3} }

// Check is one RPC check.
type Check interface {
	ID() string
	Name() string
	Description() string
	RiskLevel() RiskLevel
	Run(ctx context.Context, c *scanner.Client, o Options) CheckResult
}

// base carries the static metadata shared by every check.
type base struct {
	id, name, desc, remediation string
	risk                        RiskLevel
}

func (b base) ID() string           { return b.id }
func (b base) Name() string         { return b.name }
func (b base) Description() string  { return b.desc }
func (b base) RiskLevel() RiskLevel { return b.risk }

func (b base) result(s Status, risk RiskLevel, details interface{}) CheckResult {
	return CheckResult{
		ID: b.id, Name: b.name, Risk: risk, Status: s, Passed: s == StatusPass,
		Description: b.desc, Remediation: b.remediation, Details: details,
	}
}

func (b base) pass(details interface{}) CheckResult { return b.result(StatusPass, b.risk, details) }
func (b base) fail(risk RiskLevel, details interface{}) CheckResult {
	return b.result(StatusFail, risk, details)
}
func (b base) skipped(why string) CheckResult {
	return b.result(StatusSkipped, b.risk, map[string]string{"reason": why})
}
func (b base) errored(err error) CheckResult {
	return b.result(StatusError, b.risk, map[string]string{"error": err.Error()})
}

// exposureRisk lowers the severity of a network-exposure finding when the
// target is a loopback address, because only local processes can reach it.
func exposureRisk(r RiskLevel, loopback bool) RiskLevel {
	if loopback && r.Rank() > RiskMedium.Rank() {
		return RiskMedium
	}
	return r
}

// All returns every RPC check in a stable order (most severe first, then by id).
func All() []Check {
	list := []Check{
		NewRPCExposure(), NewAdminAPI(), NewAccounts(), NewTLS(),
		NewCORS(), NewClientVersion(), NewPeerCount(),
	}
	sort.SliceStable(list, func(i, j int) bool {
		if ri, rj := list[i].RiskLevel().Rank(), list[j].RiskLevel().Rank(); ri != rj {
			return ri > rj
		}
		return list[i].ID() < list[j].ID()
	})
	return list
}

// Summary counts results by status and, for FAIL results, by risk.
type Summary struct {
	Failed  map[RiskLevel]int `json:"failed"`
	Passed  int               `json:"passed"`
	Errors  int               `json:"errors"`
	Skipped int               `json:"skipped"`
}

// Summarize builds a Summary.
func Summarize(results []CheckResult) Summary {
	s := Summary{Failed: map[RiskLevel]int{}}
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			s.Passed++
		case StatusFail:
			s.Failed[r.Risk]++
		case StatusError:
			s.Errors++
		case StatusSkipped:
			s.Skipped++
		}
	}
	return s
}

// Worst returns the highest risk among FAIL results ("" if none).
func Worst(results []CheckResult) RiskLevel {
	var w RiskLevel
	for _, r := range results {
		if r.Status == StatusFail && r.Risk.Rank() > w.Rank() {
			w = r.Risk
		}
	}
	return w
}
