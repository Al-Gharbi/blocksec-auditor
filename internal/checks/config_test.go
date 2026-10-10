package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func audit(t *testing.T, name string) CheckResult {
	t.Helper()
	return AuditConfigFile(filepath.Join("..", "..", "testdata", name))
}

func ids(r CheckResult) map[string]int {
	out := map[string]int{}
	for _, f := range r.Details.(map[string]interface{})["findings"].([]ConfigFinding) {
		out[f.ID]++
	}
	return out
}

func TestGethDefaultIsClean(t *testing.T) {
	r := audit(t, "geth_default.toml")
	if r.Status != StatusPass {
		t.Fatalf("default geth config flagged: %+v", r.Details)
	}
}

func TestGethExposed(t *testing.T) {
	r := audit(t, "geth_exposed.toml")
	if r.Status != StatusFail || r.Risk != RiskCritical {
		t.Fatalf("got %s/%s", r.Status, r.Risk)
	}
	got := ids(r)
	// HTTP+WS public bind (2), dangerous modules on both (2), wildcard vhost (1), wildcard CORS+origins (2)
	if got["CFG-001"] != 2 || got["CFG-002"] != 2 || got["CFG-003"] != 1 || got["CFG-004"] != 2 {
		t.Errorf("findings: %v", got)
	}
}

func TestGethWildcardIPv6Bind(t *testing.T) {
	// "::" and "[::]" are wildcard binds; the original check only knew "0.0.0.0".
	for _, h := range []string{"::", "[::]", "0.0.0.0", "192.168.1.10", "node.example.com"} {
		f, _, err := AuditConfig([]byte("[Node]\nHTTPHost = \"" + h + "\"\n"))
		if err != nil || len(f) == 0 || f[0].ID != "CFG-001" {
			t.Errorf("host %q not flagged: %v %v", h, f, err)
		}
	}
	for _, h := range []string{"localhost", "127.0.0.1", "::1", "[::1]"} {
		f, _, _ := AuditConfig([]byte("[Node]\nHTTPHost = \"" + h + "\"\n"))
		if len(f) != 0 {
			t.Errorf("loopback host %q flagged: %v", h, f)
		}
	}
}

func TestGethEmptyHostMeansDisabled(t *testing.T) {
	f, _, _ := AuditConfig([]byte("[Node]\nHTTPHost = \"\"\nHTTPModules = [\"admin\"]\nWSHost = \"\"\n"))
	if len(f) != 0 {
		t.Errorf("disabled servers flagged: %v", f)
	}
}

func TestDangerousModulesOnLoopbackAreLow(t *testing.T) {
	f, _, _ := AuditConfig([]byte("[Node]\nHTTPHost = \"localhost\"\nHTTPModules = [\"eth\",\"admin\"]\n"))
	if len(f) != 1 || f[0].ID != "CFG-002" || f[0].Severity != RiskLow {
		t.Errorf("%v", f)
	}
}

func TestMalformedTypesDoNotPanic(t *testing.T) {
	r := audit(t, "geth_malformed_types.toml")
	if r.Status != StatusFail {
		t.Fatalf("got %s", r.Status)
	}
	if ids(r)["CFG-002"] != 1 {
		t.Errorf("the string element 'admin' must still be seen: %v", ids(r))
	}
}

func TestNethermindDefaultIsClean(t *testing.T) {
	if r := audit(t, "nethermind_default.json"); r.Status != StatusPass {
		t.Fatalf("%+v", r.Details)
	}
}

func TestNethermindExposedCaseInsensitive(t *testing.T) {
	r := audit(t, "nethermind_exposed.json") // keys are lower-case here on purpose
	if r.Status != StatusFail || r.Risk != RiskCritical {
		t.Fatalf("got %s/%s %+v", r.Status, r.Risk, r.Details)
	}
	got := ids(r)
	if got["CFG-001"] != 2 || got["CFG-002"] != 2 {
		t.Errorf("findings: %v", got)
	}
}

func TestNethermindDisabledOrAbsent(t *testing.T) {
	for _, js := range []string{
		`{"JsonRpc":{"Enabled":false,"Host":"0.0.0.0","EnabledModules":["Admin"]}}`,
		`{"JsonRpc":{"Host":"0.0.0.0"}}`, // Enabled defaults to false
		`{}`,
	} {
		if f, _, err := AuditConfig([]byte(js)); err != nil || len(f) != 0 {
			t.Errorf("%s -> %v %v", js, f, err)
		}
	}
}

func TestNethermindHostDefaultsToLoopback(t *testing.T) {
	f, _, _ := AuditConfig([]byte(`{"JsonRpc":{"Enabled":true,"EnabledModules":["Eth"]}}`))
	if len(f) != 0 {
		t.Errorf("%v", f)
	}
}

func TestFormatDetectedByContentNotExtension(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "mainnet.cfg") // Nethermind's historical extension
	os.WriteFile(p, []byte(`{"JsonRpc":{"Enabled":true,"Host":"0.0.0.0"}}`), 0o600)
	r := AuditConfigFile(p)
	if r.Status != StatusFail || r.Details.(map[string]interface{})["format"] != "nethermind-json" {
		t.Fatalf("%+v", r)
	}
	p2 := filepath.Join(dir, "config") // no extension at all
	os.WriteFile(p2, []byte("[Node]\nHTTPHost=\"0.0.0.0\"\n"), 0o600)
	if r := AuditConfigFile(p2); r.Status != StatusFail {
		t.Fatalf("%+v", r)
	}
}

func TestUnparseableConfigIsErrorNotPass(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.toml")
	os.WriteFile(p, []byte("this is = = not toml ["), 0o600)
	if r := AuditConfigFile(p); r.Status != StatusError {
		t.Fatalf("got %s", r.Status)
	}
	if r := AuditConfigFile(filepath.Join(dir, "missing")); r.Status != StatusError {
		t.Fatalf("missing file: got %s", r.Status)
	}
	p3 := filepath.Join(dir, "bad.json")
	os.WriteFile(p3, []byte(`{"JsonRpc": `), 0o600)
	if r := AuditConfigFile(p3); r.Status != StatusError {
		t.Fatalf("bad json: got %s", r.Status)
	}
}

func TestOversizedConfigRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.toml")
	os.WriteFile(p, []byte("# "+strings.Repeat("a", maxConfigBytes+10)), 0o600)
	if r := AuditConfigFile(p); r.Status != StatusError {
		t.Fatalf("got %s", r.Status)
	}
}

func TestBOMTolerated(t *testing.T) {
	f, format, err := AuditConfig([]byte("\xef\xbb\xbf{\"JsonRpc\":{\"Enabled\":true,\"Host\":\"0.0.0.0\"}}"))
	if err != nil || format != "nethermind-json" || len(f) == 0 {
		t.Fatalf("%v %s %v", f, format, err)
	}
}
