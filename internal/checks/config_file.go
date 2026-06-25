package checks

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

type ConfigFileCheck struct{}

func (c *ConfigFileCheck) Name() string { return "Configuration File Weaknesses" }
func (c *ConfigFileCheck) Description() string {
	return "Analyzes Geth TOML or Nethermind JSON config files for insecure settings"
}
func (c *ConfigFileCheck) RiskLevel() RiskLevel { return RiskHigh }

func (c *ConfigFileCheck) Run(ctx context.Context, client *any) (CheckResult, error) {
	return CheckResult{}, nil
}

func (c *ConfigFileCheck) RunFile(ctx context.Context, path string) (CheckResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CheckResult{}, err
	}
	issues := []string{}
	if strings.HasSuffix(path, ".toml") {
		var cfg map[string]interface{}
		if err := toml.Unmarshal(data, &cfg); err != nil {
			return CheckResult{}, err
		}
		if node, ok := cfg["Node"].(map[string]interface{}); ok {
			if httpHost, ok := node["HTTPHost"].(string); ok && httpHost == "0.0.0.0" {
				issues = append(issues, "HTTPHost is 0.0.0.0 (public)")
			}
			if httpMods, ok := node["HTTPModules"].([]interface{}); ok {
				for _, m := range httpMods {
					mod := m.(string)
					if mod == "admin" || mod == "personal" {
						issues = append(issues, "HTTPModules includes dangerous module: "+mod)
					}
				}
			}
			if vHosts, ok := node["HTTPVirtualHosts"].([]interface{}); ok {
				for _, v := range vHosts {
					if v.(string) == "*" {
						issues = append(issues, "HTTPVirtualHosts contains '*'")
					}
				}
			}
		}
	} else if strings.HasSuffix(path, ".json") {
		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return CheckResult{}, err
		}
		if jrpc, ok := cfg["JsonRpc"].(map[string]interface{}); ok {
			if host, ok := jrpc["Host"].(string); ok && host == "0.0.0.0" {
				issues = append(issues, "JsonRpc.Host is 0.0.0.0")
			}
		}
	}
	passed := len(issues) == 0
	return CheckResult{
		Name:        c.Name(),
		Risk:        c.RiskLevel(),
		Description: c.Description(),
		Remediation: "Change insecure settings: bind to localhost, restrict modules, set specific virtual hosts.",
		Passed:      passed,
		Details:     map[string]interface{}{"issues": issues, "file": path},
	}, nil
}
