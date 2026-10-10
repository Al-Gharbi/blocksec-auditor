// Package report renders audit results as text, JSON or HTML.
package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/Al-Gharbi/blocksec-auditor/internal/checks"
	"github.com/Al-Gharbi/blocksec-auditor/internal/vulndb"
)

//go:embed templates/report.html
var htmlTemplate string

// Report is the full audit output.
type Report struct {
	Tool      string               `json:"tool"`
	Version   string               `json:"version"`
	Target    string               `json:"target"`
	Timestamp string               `json:"timestamp"`
	Summary   checks.Summary       `json:"summary"`
	Results   []checks.CheckResult `json:"results"`
}

// New builds a Report. target is what was scanned (URL or file path).
func New(version, target string, now time.Time, results []checks.CheckResult) Report {
	return Report{
		Tool: "blocksec-auditor", Version: version, Target: target,
		Timestamp: now.UTC().Format(time.RFC3339),
		Summary:   checks.Summarize(results),
		Results:   results,
	}
}

// JSON writes the report as indented JSON.
func (r Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// HTML writes the report as a self-contained HTML page. html/template escapes
// every value: data returned by the audited node (e.g. its client version
// string) is attacker-controlled and must never be able to inject markup.
func (r Report) HTML(w io.Writer) error {
	t, err := template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
		"detail": func(v interface{}) string {
			b, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return fmt.Sprint(v)
			}
			return string(b)
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return t.Execute(w, r)
}

// Text writes a compact human-readable summary. color enables ANSI colors.
func (r Report) Text(w io.Writer, color bool) {
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	fmt.Fprintf(w, "blocksec-auditor %s  target: %s\n\n", r.Version, sanitize(r.Target))
	for _, res := range r.Results {
		var tag string
		switch res.Status {
		case checks.StatusPass:
			tag = paint("32", "PASS   ")
		case checks.StatusFail:
			tag = paint("31", "FAIL   ")
		case checks.StatusError:
			tag = paint("35", "ERROR  ")
		default:
			tag = paint("33", "SKIPPED")
		}
		fmt.Fprintf(w, "%s [%-8s] %s  %s\n", tag, res.Risk, res.ID, res.Name)
		if res.Status != checks.StatusPass {
			if note := briefDetail(res); note != "" {
				fmt.Fprintf(w, "         %s\n", note)
			}
		}
	}
	s := r.Summary
	fmt.Fprintf(w, "\n%d passed, %d failed, %d error, %d skipped", s.Passed, countFailed(s), s.Errors, s.Skipped)
	if len(s.Failed) > 0 {
		var parts []string
		for _, lvl := range []checks.RiskLevel{checks.RiskCritical, checks.RiskHigh, checks.RiskMedium, checks.RiskLow} {
			if n := s.Failed[lvl]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, lvl))
			}
		}
		fmt.Fprintf(w, "  (failed: %s)", strings.Join(parts, ", "))
	}
	fmt.Fprintln(w)
	if s.Errors > 0 || s.Skipped > 0 {
		fmt.Fprintln(w, "ERROR/SKIPPED checks were not assessed; they are not passes.")
	}
}

func countFailed(s checks.Summary) int {
	n := 0
	for _, v := range s.Failed {
		n += v
	}
	return n
}

// briefDetail extracts a one-line reason from a result's details.
func briefDetail(r checks.CheckResult) string {
	if m, ok := r.Details.(map[string]string); ok {
		for _, k := range []string{"reason", "error", "problem", "result"} {
			if v := m[k]; v != "" {
				return sanitize(v)
			}
		}
	}
	if m, ok := r.Details.(map[string]interface{}); ok {
		for _, k := range []string{"problem", "reason", "note", "error"} {
			if v, ok := m[k].(string); ok && v != "" {
				return sanitize(v)
			}
		}
		if ex, ok := m["exposed"].([]string); ok && len(ex) > 0 {
			return "exposed: " + sanitize(strings.Join(ex, ", "))
		}
		if vs, ok := m["vulnerabilities"].([]vulndb.Vulnerability); ok && len(vs) > 0 {
			var ids []string
			for _, v := range vs {
				ids = append(ids, v.CVE)
			}
			up, _ := m["upgrade_to_at_least"].(string)
			return sanitize(fmt.Sprintf("%s; upgrade to >= %s", strings.Join(ids, ", "), up))
		}
		if n, ok := m["peer_count"].(uint64); ok {
			return fmt.Sprintf("%d peer(s), minimum %v", n, m["minimum"])
		}
		if fs, ok := m["findings"].([]checks.ConfigFinding); ok && len(fs) > 0 {
			return fmt.Sprintf("%d finding(s); first: %s", len(fs), sanitize(fs[0].Message))
		}
	}
	return ""
}

// sanitize strips control characters (including ANSI escapes) from strings
// that may originate from the audited node before they reach a terminal.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
