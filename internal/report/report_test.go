package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Al-Gharbi/blocksec-auditor/internal/checks"
	"github.com/Al-Gharbi/blocksec-auditor/internal/vulndb"
)

var results = []checks.CheckResult{
	{ID: "A", Name: "Pass check", Risk: checks.RiskLow, Status: checks.StatusPass, Passed: true},
	{ID: "B", Name: "Fail check", Risk: checks.RiskHigh, Status: checks.StatusFail, Remediation: "fix it",
		Details: map[string]string{"problem": "bad thing"}},
	{ID: "C", Name: "Err check", Risk: checks.RiskMedium, Status: checks.StatusError,
		Details: map[string]string{"error": "boom"}},
	{ID: "D", Name: "Skip check", Risk: checks.RiskLow, Status: checks.StatusSkipped,
		Details: map[string]string{"reason": "n/a"}},
}

func rep(target string, rs []checks.CheckResult) Report {
	return New("9.9.9", target, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), rs)
}

func TestJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := rep("http://x", results).JSON(&buf); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Timestamp != "2026-01-02T03:04:05Z" || len(back.Results) != 4 || back.Summary.Errors != 1 || back.Summary.Skipped != 1 || back.Summary.Failed[checks.RiskHigh] != 1 {
		t.Errorf("%+v", back)
	}
	if back.Results[1].Passed || !back.Results[0].Passed {
		t.Error("passed flag wrong")
	}
}

func TestTextShowsEveryStatusAndWarns(t *testing.T) {
	var buf bytes.Buffer
	rep("http://x", results).Text(&buf, false)
	out := buf.String()
	for _, want := range []string{"PASS", "FAIL", "ERROR", "SKIPPED", "bad thing", "boom", "n/a", "1 passed, 1 failed, 1 error, 1 skipped", "not passes"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("color disabled but ANSI present")
	}
}

func TestTextColorAndSanitizesNodeControlledStrings(t *testing.T) {
	rs := []checks.CheckResult{{ID: "X", Name: "n", Risk: checks.RiskLow, Status: checks.StatusSkipped,
		Details: map[string]string{"reason": "evil \x1b[2J\x1b[31m text"}}}
	var buf bytes.Buffer
	rep("http://x\x1b]0;pwn\x07", rs).Text(&buf, false)
	if strings.ContainsAny(buf.String(), "\x1b\x07") {
		t.Errorf("control characters leaked to terminal output: %q", buf.String())
	}
	buf.Reset()
	rep("t", results).Text(&buf, true)
	if !strings.Contains(buf.String(), "\x1b[31m") {
		t.Error("expected color")
	}
}

// The node's client-version string is attacker-controlled. The original used
// text/template, so markup in it would have been written to the report verbatim.
func TestHTMLEscapesNodeControlledData(t *testing.T) {
	evil := `<script>alert(1)</script>`
	rs := []checks.CheckResult{{ID: "V", Name: evil, Risk: checks.RiskMedium, Status: checks.StatusFail,
		Description: evil, Remediation: evil,
		Details: map[string]string{"client_version": evil}}}
	var buf bytes.Buffer
	if err := rep(evil, rs).HTML(&buf); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>alert(1)") {
		t.Fatalf("unescaped markup in HTML report:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "&lt;script&gt;") {
		t.Error("expected escaped text")
	}
}

func TestHTMLContainsAllResults(t *testing.T) {
	var buf bytes.Buffer
	if err := rep("http://x", results).HTML(&buf); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Pass check", "Fail check", "Err check", "Skip check", "fix it", "not assessed"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(buf.String(), "fix it") && strings.Count(buf.String(), "Remediation") != 1 {
		t.Error("remediation should appear only for non-passing checks")
	}
}

func TestTextExplainsVersionAndPeerFailures(t *testing.T) {
	rs := []checks.CheckResult{
		{ID: "V", Name: "ver", Risk: checks.RiskHigh, Status: checks.StatusFail, Details: map[string]interface{}{
			"vulnerabilities":     []vulndb.Vulnerability{{CVE: "CVE-2021-39137"}, {CVE: "CVE-2022-29177"}},
			"upgrade_to_at_least": "1.13.15"}},
		{ID: "P", Name: "peers", Risk: checks.RiskLow, Status: checks.StatusFail, Details: map[string]interface{}{
			"peer_count": uint64(2), "minimum": 3}},
	}
	var buf bytes.Buffer
	rep("t", rs).Text(&buf, false)
	for _, want := range []string{"CVE-2021-39137, CVE-2022-29177; upgrade to >= 1.13.15", "2 peer(s), minimum 3"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q in %s", want, buf.String())
		}
	}
}
