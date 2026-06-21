package checks

import (
	"context"

	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
)

type RPCExposureCheck struct{}

func init() { Register(&RPCExposureCheck{}) }

func (c *RPCExposureCheck) Name() string        { return "RPC Public Exposure" }
func (c *RPCExposureCheck) Description() string  { return "Checks if JSON-RPC endpoint responds without authentication" }
func (c *RPCExposureCheck) RiskLevel() RiskLevel { return RiskCritical }

func (c *RPCExposureCheck) Run(ctx context.Context, client *scanner.Client) (CheckResult, error) {
	_, err := client.Call(ctx, "net_version", nil)
	if err != nil {
		return CheckResult{
			Name:        c.Name(),
			Risk:        c.RiskLevel(),
			Description: c.Description(),
			Remediation: "Bind RPC to localhost (127.0.0.1) and use authentication (JWT).",
			Passed:      true,
			Details:     map[string]string{"error": err.Error()},
		}, nil
	}
	return CheckResult{
		Name:        c.Name(),
		Risk:        c.RiskLevel(),
		Description: c.Description(),
		Remediation: "Bind RPC to localhost (127.0.0.1) and use authentication (JWT).",
		Passed:      false,
		Details:     map[string]string{"method": "net_version", "status": "accessible"},
	}, nil
}
