package checks

import (
	"context"
	"encoding/json"

	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
)

type UnlockedAccountsCheck struct{}

func init() { Register(&UnlockedAccountsCheck{}) }

func (c *UnlockedAccountsCheck) Name() string        { return "Unlocked Accounts" }
func (c *UnlockedAccountsCheck) Description() string  { return "Checks if any accounts are currently unlocked on the node" }
func (c *UnlockedAccountsCheck) RiskLevel() RiskLevel { return RiskHigh }

func (c *UnlockedAccountsCheck) Run(ctx context.Context, client *scanner.Client) (CheckResult, error) {
	result, err := client.Call(ctx, "eth_accounts", nil)
	if err != nil {
		return CheckResult{
			Name:        c.Name(),
			Risk:        c.RiskLevel(),
			Description: c.Description(),
			Remediation: "Never leave accounts unlocked on a node. Use a dedicated signer or require passphrase.",
			Passed:      true,
			Details:     map[string]string{"error": err.Error()},
		}, nil
	}
	var accounts []string
	if err := json.Unmarshal(result, &accounts); err != nil {
		return CheckResult{}, err
	}
	passed := len(accounts) == 0
	return CheckResult{
		Name:        c.Name(),
		Risk:        c.RiskLevel(),
		Description: c.Description(),
		Remediation: "Never leave accounts unlocked on a node. Use a dedicated signer or require passphrase.",
		Passed:      passed,
		Details:     map[string]interface{}{"accounts_count": len(accounts)},
	}, nil
}
