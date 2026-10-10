package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func exec(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func node(t *testing.T, results map[string]string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			return
		}
		var req struct{ Method string }
		json.NewDecoder(r.Body).Decode(&req)
		if res, ok := results[req.Method]; ok {
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":` + res + `}`))
			return
		}
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"the method ` + req.Method + ` does not exist/is not available"}}`))
	}))
	t.Cleanup(s.Close)
	return s
}

func TestUsageAndVersion(t *testing.T) {
	if c, _, e := exec(); c != exitError || !strings.Contains(e, "Usage") {
		t.Errorf("no args: %d %q", c, e)
	}
	if c, o, _ := exec("version"); c != exitOK || !strings.HasPrefix(o, "blocksec-auditor ") {
		t.Errorf("version: %d %q", c, o)
	}
	if c, _, _ := exec("nope"); c != exitError {
		t.Errorf("unknown command: %d", c)
	}
}

func TestArgumentValidation(t *testing.T) {
	for _, args := range [][]string{
		{"audit"},
		{"audit", "--rpc-url", "ftp://x"},
		{"audit", "--rpc-url", "http://"},
		{"audit", "--rpc-url", "http://127.0.0.1:1", "--output", "xml"},
		{"audit", "--rpc-url", "http://127.0.0.1:1", "--fail-on", "severe"},
		{"audit", "--rpc-url", "http://127.0.0.1:1", "--min-peers", "-1"},
		{"audit", "--rpc-url", "http://127.0.0.1:1", "extra"},
	} {
		if c, _, _ := exec(args...); c != exitError {
			t.Errorf("%v: exit %d, want %d", args, c, exitError)
		}
	}
}

// Regression: with the original tool, pointing it at a dead endpoint produced
// a report in which almost every check was "passed".
func TestUnreachableEndpointIsAnErrorNotAPassingReport(t *testing.T) {
	c, out, e := exec("audit", "--rpc-url", "http://127.0.0.1:1", "--timeout", "500ms", "--output", "json")
	if c != exitError {
		t.Fatalf("exit %d", c)
	}
	if out != "" || !strings.Contains(e, "not a reachable JSON-RPC endpoint") {
		t.Errorf("stdout=%q stderr=%q", out, e)
	}
}

func TestNonJSONRPCServerIsRejected(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>")) }))
	defer s.Close()
	if c, _, _ := exec("audit", "--rpc-url", s.URL); c != exitError {
		t.Errorf("exit %d", c)
	}
}

func TestJSONOutputIsPureJSON(t *testing.T) {
	s := node(t, map[string]string{"web3_clientVersion": `"Geth/v1.10.7-stable-aa/linux-amd64/go1.16"`, "net_peerCount": `"0x1"`, "eth_accounts": `[]`})
	c, out, _ := exec("audit", "--rpc-url", s.URL, "--output", "json")
	if c != exitOK {
		t.Fatalf("exit %d", c)
	}
	var rep map[string]interface{}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("stdout is not clean JSON (the original mixed colored text into it): %v\n%s", err, out)
	}
	if rep["tool"] != "blocksec-auditor" || len(rep["results"].([]interface{})) != 7 {
		t.Errorf("%v", rep)
	}
}

func TestFailOn(t *testing.T) {
	s := node(t, map[string]string{"web3_clientVersion": `"Geth/v1.10.7-stable-aa/linux-amd64/go1.16"`})
	for failOn, want := range map[string]int{"none": exitOK, "critical": exitOK, "high": exitFindings, "low": exitFindings} {
		if c, _, _ := exec("audit", "--rpc-url", s.URL, "--output", "json", "--fail-on", failOn); c != want {
			t.Errorf("--fail-on %s: exit %d want %d", failOn, c, want)
		}
	}
}

func TestOutputFile(t *testing.T) {
	s := node(t, map[string]string{"web3_clientVersion": `"Geth/v1.14.0-stable-aa/linux-amd64/go1.22"`})
	p := filepath.Join(t.TempDir(), "r.html")
	c, out, e := exec("audit", "--rpc-url", s.URL, "--output", "html", "--output-file", p)
	if c != exitOK || out != "" || !strings.Contains(e, "report written") {
		t.Fatalf("%d %q %q", c, out, e)
	}
	b, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(b), "<html") {
		t.Fatalf("%v", err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("report file mode %v, want 0600", st.Mode().Perm())
	}
	if c, _, _ := exec("audit", "--rpc-url", s.URL, "--output-file", filepath.Join(t.TempDir(), "no", "dir", "r.txt")); c != exitError {
		t.Errorf("unwritable path: exit %d", c)
	}
}

func TestConfigFileMode(t *testing.T) {
	td := filepath.Join("..", "..", "testdata")
	c, out, _ := exec("audit", "--config-file", filepath.Join(td, "geth_exposed.toml"), "--output", "json", "--fail-on", "high")
	if c != exitFindings || !strings.Contains(out, "BSA-CFG-001") {
		t.Errorf("exposed: exit %d\n%s", c, out)
	}
	if c, _, _ := exec("audit", "--config-file", filepath.Join(td, "geth_default.toml"), "--fail-on", "low"); c != exitOK {
		t.Errorf("clean config: exit %d", c)
	}
	if c, _, _ := exec("audit", "--config-file", "/nonexistent/x.toml", "--output", "json"); c != exitOK {
		// a missing file is an ERROR result (reported), and ERROR is not a finding
		t.Errorf("missing config: exit %d", c)
	}
}

func TestTextOutputDefaultHasNoANSIWhenNotATerminal(t *testing.T) {
	s := node(t, map[string]string{"web3_clientVersion": `"Geth/v1.14.0-stable-aa/linux-amd64/go1.22"`})
	_, out, _ := exec("audit", "--rpc-url", s.URL)
	if strings.Contains(out, "\x1b[") || !strings.Contains(out, "BSA-VER-001") {
		t.Errorf("%q", out)
	}
}
