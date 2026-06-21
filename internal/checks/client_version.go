package checks

import (
	"context"
	"encoding/json"

	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
	"github.com/Al-Gharbi/blocksec-auditor/internal/vulndb"
)

type ClientVersionCheck struct{}

func init() { Register(&ClientVersionCheck{}) }

func (c *ClientVersionCheck) Name() string        { return "Outdated Client / Known CVEs" }
func (c *ClientVersionCheck) Description() string  { return "Checks client version and compares against known vulnerabilities" }
func (c *ClientVersionCheck) RiskLevel() RiskLevel { return RiskMedium }

func (c *ClientVersionCheck) Run(ctx context.Context, client *scanner.Client) (CheckResult, error) {
	raw, err := client.Call(ctx, "web3_clientVersion", nil)
	if err != nil {
		return CheckResult{
			Name:        c.Name(),
			Risk:        c.RiskLevel(),
			Description: c.Description(),
			Remediation: "Update your node client to the latest stable version.",
			Passed:      true,
			Details:     map[string]string{"error": err.Error()},
		}, nil
	}
	var version string
	if err := json.Unmarshal(raw, &version); err != nil {
		return CheckResult{}, err
	}
	vulns := vulndb.Check(version)
	passed := len(vulns) == 0
	return CheckResult{
		Name:        c.Name(),
		Risk:        c.RiskLevel(),
		Description: c.Description(),
		Remediation: "Upgrade to a version that patches these vulnerabilities.",
		Passed:      passed,
		Details: map[string]interface{}{
			"client_version": version,
			"vulnerabilities": vulns,
		},
	}, nil
}
