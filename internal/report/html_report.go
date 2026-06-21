package report

import (
	"bytes"
	_ "embed"
	"text/template"

	"github.com/Al-Gharbi/blocksec-auditor/internal/checks"
)

//go:embed templates/report.html
var htmlTemplate string

func NewHTMLReport(results []checks.CheckResult) string {
	tmpl, _ := template.New("report").Parse(htmlTemplate)
	var buf bytes.Buffer
	_ = tmpl.Execute(&buf, map[string]interface{}{
		"Results": results,
	})
	return buf.String()
}
