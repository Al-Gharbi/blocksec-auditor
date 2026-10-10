package checks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
)

// ConfigFinding is one problem found in a node configuration file.
type ConfigFinding struct {
	ID       string    `json:"id"`
	Severity RiskLevel `json:"severity"`
	Message  string    `json:"message"`
}

const maxConfigBytes = 5 << 20

// dangerousModules are RPC modules that must not be exposed over network RPC.
var dangerousModules = map[string]bool{"admin": true, "personal": true, "debug": true, "miner": true}

// AuditConfigFile statically audits a Geth (TOML) or Nethermind (JSON) config
// file. The format is detected from the content, not the extension: Nethermind
// ships JSON configs under several names (.json, historically .cfg).
func AuditConfigFile(path string) CheckResult {
	b := base{
		id: "BSA-CFG-001", name: "Configuration File Weaknesses", risk: RiskHigh,
		desc:        "Static analysis of a Geth (TOML) or Nethermind (JSON) configuration for network-exposed RPC",
		remediation: "Bind RPC to 127.0.0.1, expose only eth/net/web3, set explicit virtual hosts and CORS origins.",
	}
	f, err := os.Open(path)
	if err != nil {
		return b.errored(err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return b.errored(err)
	}
	if len(data) > maxConfigBytes {
		return b.errored(fmt.Errorf("config file larger than %d bytes", maxConfigBytes))
	}
	findings, format, err := AuditConfig(data)
	if err != nil {
		return b.errored(err)
	}
	d := map[string]interface{}{"file": path, "format": format, "findings": findings}
	if len(findings) == 0 {
		return b.pass(d)
	}
	worst := RiskLow
	for _, f := range findings {
		if f.Severity.Rank() > worst.Rank() {
			worst = f.Severity
		}
	}
	return b.fail(worst, d)
}

// AuditConfig audits config bytes. It returns the findings and the detected
// format ("geth-toml" or "nethermind-json").
func AuditConfig(data []byte) ([]ConfigFinding, string, error) {
	trim := bytes.TrimLeft(data, "\xef\xbb\xbf \t\r\n")
	if len(trim) > 0 && trim[0] == '{' {
		var cfg map[string]interface{}
		if err := json.Unmarshal(trim, &cfg); err != nil {
			return nil, "", fmt.Errorf("invalid JSON config: %w", err)
		}
		return auditNethermind(cfg), "nethermind-json", nil
	}
	var cfg map[string]interface{}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, "", fmt.Errorf("config is neither valid JSON nor valid TOML: %w", err)
	}
	return auditGeth(cfg), "geth-toml", nil
}

// ---- helpers ---------------------------------------------------------------

// lookup finds a key case-insensitively (Nethermind config keys are
// case-insensitive; Geth's are exact but this is harmless).
func lookup(m map[string]interface{}, key string) (interface{}, bool) {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

func section(m map[string]interface{}, key string) map[string]interface{} {
	v, _ := lookup(m, key)
	s, _ := v.(map[string]interface{})
	return s
}

func str(m map[string]interface{}, key string) (string, bool) {
	v, ok := lookup(m, key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// strList accepts []interface{} (TOML/JSON arrays) and []string, skipping
// non-string elements instead of panicking on them.
func strList(m map[string]interface{}, key string) []string {
	v, ok := lookup(m, key)
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// isNetworkHost reports whether binding to host exposes the port beyond the
// local machine: anything that is not localhost or a loopback IP, including
// wildcard addresses ("0.0.0.0", "::", "[::]", "").
func isNetworkHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return true
	}
	return !scanner.IsLoopbackHost(h)
}

type collector struct{ out []ConfigFinding }

func (c *collector) add(id string, sev RiskLevel, format string, a ...interface{}) {
	c.out = append(c.out, ConfigFinding{ID: id, Severity: sev, Message: fmt.Sprintf(format, a...)})
}

// surface audits one RPC listener (HTTP or WS).
func (c *collector) surface(label, host string, modules, vhosts, origins []string) {
	public := isNetworkHost(host)
	if public {
		c.add("CFG-001", RiskHigh, "%s listens on a non-loopback address (%q)", label, host)
	}
	var danger []string
	for _, m := range modules {
		if dangerousModules[strings.ToLower(m)] {
			danger = append(danger, m)
		}
	}
	if len(danger) > 0 {
		sev := RiskLow
		where := "loopback only"
		if public {
			sev, where = RiskCritical, "on a network-reachable listener"
		}
		c.add("CFG-002", sev, "%s exposes dangerous module(s) %s (%s)", label, strings.Join(danger, ", "), where)
	}
	for _, v := range vhosts {
		if v == "*" {
			c.add("CFG-003", RiskMedium, "%s accepts any virtual host (\"*\"), enabling DNS-rebinding attacks", label)
			break
		}
	}
	for _, o := range origins {
		if o == "*" {
			c.add("CFG-004", RiskMedium, "%s allows any web origin (\"*\")", label)
			break
		}
	}
}

func (c *collector) sorted() []ConfigFinding {
	sort.SliceStable(c.out, func(i, j int) bool {
		if a, b := c.out[i].Severity.Rank(), c.out[j].Severity.Rank(); a != b {
			return a > b
		}
		return c.out[i].ID < c.out[j].ID
	})
	return c.out
}

// ---- Geth ------------------------------------------------------------------

// Geth keeps all RPC settings in the [Node] table (node.Config). An empty
// HTTPHost / WSHost means that server is disabled.
func auditGeth(cfg map[string]interface{}) []ConfigFinding {
	var c collector
	node := section(cfg, "Node")
	if node == nil {
		return nil
	}
	if host, ok := str(node, "HTTPHost"); ok && host != "" {
		c.surface("HTTP RPC", host, strList(node, "HTTPModules"), strList(node, "HTTPVirtualHosts"), strList(node, "HTTPCors"))
	}
	if host, ok := str(node, "WSHost"); ok && host != "" {
		c.surface("WebSocket RPC", host, strList(node, "WSModules"), nil, strList(node, "WSOrigins"))
	}
	for _, v := range strList(node, "GraphQLVirtualHosts") {
		if v == "*" {
			c.add("CFG-003", RiskMedium, "GraphQL accepts any virtual host (\"*\")")
			break
		}
	}
	return c.sorted()
}

// ---- Nethermind --------------------------------------------------------------

// Nethermind: JsonRpc.{Enabled,Host,EnabledModules,AdditionalRpcUrls}. Host
// defaults to 127.0.0.1 and RPC is off unless Enabled is true.
func auditNethermind(cfg map[string]interface{}) []ConfigFinding {
	var c collector
	j := section(cfg, "JsonRpc")
	if j == nil {
		return nil
	}
	if v, ok := lookup(j, "Enabled"); ok {
		if en, isBool := v.(bool); isBool && !en {
			return nil
		}
	} else {
		return nil // RPC is disabled by default
	}
	host := "127.0.0.1"
	if h, ok := str(j, "Host"); ok {
		host = h
	}
	c.surface("JSON-RPC", host, strList(j, "EnabledModules"), nil, nil)
	// AdditionalRpcUrls entries look like "http://host:port|http;ws|mod1;mod2".
	for _, e := range strList(j, "AdditionalRpcUrls") {
		parts := strings.Split(e, "|")
		u, err := url.Parse(parts[0])
		if err != nil || u.Host == "" {
			continue
		}
		h := u.Hostname()
		if h == "" {
			continue
		}
		var mods []string
		if len(parts) >= 3 {
			mods = strings.Split(parts[2], ";")
		}
		c.surface("Additional endpoint "+parts[0], h, mods, nil, nil)
	}
	return c.sorted()
}
