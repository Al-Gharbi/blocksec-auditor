package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
)

type AdminAPICheck struct{}

func init() { Register(&AdminAPICheck{}) }

func (c *AdminAPICheck) Name() string { return "Admin API Exposed" }
func (c *AdminAPICheck) Description() string {
	return "Tests if dangerous admin/personal APIs are enabled on the public endpoint"
}
func (c *AdminAPICheck) RiskLevel() RiskLevel { return RiskCritical }

func (c *AdminAPICheck) Run(ctx context.Context, client *scanner.Client) (CheckResult, error) {
	exposed := []string{}
	methods := []string{"admin_nodeInfo", "personal_listWallets", "personal_newAccount"}
	for _, m := range methods {
		_, err := client.Call(ctx, m, nil)
		if err == nil {
			exposed = append(exposed, m)
		} else if err != nil && (strings.Contains(err.Error(), "Method not found") || strings.Contains(err.Error(), "not available")) {
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

type PeerCountCheck struct{}

func init() { Register(&PeerCountCheck{}) }

func (c *PeerCountCheck) Name() string { return "Low Peer Count" }
func (c *PeerCountCheck) Description() string {
	return "Checks if the node is connected to enough peers to prevent eclipse attacks"
}
func (c *PeerCountCheck) RiskLevel() RiskLevel { return RiskMedium }

func (c *PeerCountCheck) Run(ctx context.Context, client *scanner.Client) (CheckResult, error) {
	result, err := client.Call(ctx, "net_peerCount", nil)
	if err != nil {
		return CheckResult{
			Name: c.Name(), Risk: c.RiskLevel(), Description: c.Description(),
			Passed: true, Details: map[string]string{"error": "Method net_peerCount not supported"},
		}, nil
	}
	var hexCount string
	json.Unmarshal(result, &hexCount)
	// Convert hex to int
	var count int
	fmt.Sscanf(hexCount, "0x%x", &count)

	passed := count >= 3
	return CheckResult{
		Name:        c.Name(),
		Risk:        c.RiskLevel(),
		Description: c.Description(),
		Remediation: "Ensure the node has stable internet and proper discovery settings to connect to more peers.",
		Passed:      passed,
		Details:     map[string]interface{}{"peer_count": count},
	}, nil
}
