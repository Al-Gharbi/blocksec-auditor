package checks

import (
	"context"
	"net/url"

	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
)

type TLSCheck struct{}

func init() { Register(&TLSCheck{}) }

func (c *TLSCheck) Name() string         { return "TLS Not Enabled" }
func (c *TLSCheck) Description() string  { return "Verifies HTTPS/TLS is used for the RPC connection" }
func (c *TLSCheck) RiskLevel() RiskLevel { return RiskHigh }

func (c *TLSCheck) Run(ctx context.Context, client *scanner.Client) (CheckResult, error) {
	u, err := url.Parse(client.Endpoint)
	if err != nil {
		return CheckResult{}, err
	}
	passed := u.Scheme == "https"
	return CheckResult{
		Name:        c.Name(),
		Risk:        c.RiskLevel(),
		Description: c.Description(),
		Remediation: "Enable TLS by using a reverse proxy like Nginx with Let's Encrypt, or configure the node with certificates.",
		Passed:      passed,
		Details:     map[string]string{"scheme": u.Scheme},
	}, nil
}
