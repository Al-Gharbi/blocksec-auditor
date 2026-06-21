package checks

import (
	"context"
	"strings"

	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
)

type AdminAPICheck struct{}

func init() { Register(&AdminAPICheck{}) }

func (c *AdminAPICheck) Name() string        { return "Admin API Exposed" }
func (c *AdminAPICheck) Description() string  { return "Tests if dangerous admin/personal APIs are enabled on the public endpoint" }
func (c *AdminAPICheck) RiskLevel() RiskLevel { return RiskCritical }

func (c *AdminAPICheck) Run(ctx context.Context, client *scanner.Client) (CheckResult, error) {
	exposed := []string{}
	methods := []string{"admin_nodeInfo", "personal_listWallets", "personal_newAccount"}
	for _, m := range methods {
		_, err := client.Call(ctx, m, nil)
		if err == nil {
			exposed = append(exposed, m)
		} else if strings.Contains(err.Error(), "Method not found") || strings.Contains(err.Error(), "not available") {
			continue
		} else {
			continue
		}
	}
	passed := len(exposed) == 0
	return CheckResult{
		Name:        c.Name(),
		Risk:        c.RiskLevel(),
		Description: c.Description(),
		Remediation: "Disable admin and personal APIs on public interfaces or secure them with strong authentication.",
		Passed:      passed,
		Details:     map[string]interface{}{"exposed_apis": exposed},
	}, nil
}
