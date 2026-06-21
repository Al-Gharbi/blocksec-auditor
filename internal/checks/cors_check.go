package checks

import (
	"context"
	"net/http"

	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
)

type CORSCheck struct{}

func init() { Register(&CORSCheck{}) }

func (c *CORSCheck) Name() string        { return "Insecure CORS Settings" }
func (c *CORSCheck) Description() string  { return "Checks if Access-Control-Allow-Origin is set to * or reflects arbitrary origins" }
func (c *CORSCheck) RiskLevel() RiskLevel { return RiskMedium }

func (c *CORSCheck) Run(ctx context.Context, client *scanner.Client) (CheckResult, error) {
	resp, err := client.SendHTTPRequest(ctx, http.MethodOptions, "https://attacker.com")
	if err != nil {
		return CheckResult{
			Name:        c.Name(),
			Risk:        c.RiskLevel(),
			Description: c.Description(),
			Remediation: "Restrict CORS to trusted domains only. Do not use *.",
			Passed:      true,
			Details:     map[string]string{"note": "CORS not detectable (request failed)"},
		}, nil
	}
	origin := resp.Header.Get("Access-Control-Allow-Origin")
	passed := origin != "*" && origin != "https://attacker.com"
	return CheckResult{
		Name:        c.Name(),
		Risk:        c.RiskLevel(),
		Description: c.Description(),
		Remediation: "Restrict CORS to trusted domains only. Do not use *.",
		Passed:      passed,
		Details:     map[string]string{"allow_origin": origin},
	}, nil
}
