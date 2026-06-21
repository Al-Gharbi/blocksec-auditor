package checks

import "sort"

var registry []Check

func Register(c Check) {
	registry = append(registry, c)
}

func AllChecks() []Check {
	sort.Slice(registry, func(i, j int) bool {
		return severityOrder(registry[i].RiskLevel()) < severityOrder(registry[j].RiskLevel())
	})
	return registry
}

func severityOrder(r RiskLevel) int {
	switch r {
	case RiskCritical:
		return 0
	case RiskHigh:
		return 1
	case RiskMedium:
		return 2
	case RiskLow:
		return 3
	}
	return 4
}
