package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/Al-Gharbi/blocksec-auditor/internal/checks"
	"github.com/Al-Gharbi/blocksec-auditor/internal/report"
	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
)

var (
	rpcURL     string
	configFile string
	outputFmt  string
	outputFile string
)

var rootCmd = &cobra.Command{
	Use:   "blocksec-auditor",
	Short: "Security auditor for EVM nodes",
	Long:  `Audit Ethereum / EVM node security by connecting to JSON-RPC or analyzing configuration files.`,
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run audit",
	RunE:  runAudit,
}

func init() {
	auditCmd.Flags().StringVar(&rpcURL, "rpc-url", "", "JSON-RPC endpoint (e.g., http://localhost:8545)")
	auditCmd.Flags().StringVar(&configFile, "config-file", "", "Path to node config file")
	auditCmd.Flags().StringVar(&outputFmt, "output", "json", "Report format: json or html")
	auditCmd.Flags().StringVar(&outputFile, "output-file", "", "Write report to file")
	rootCmd.AddCommand(auditCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runAudit(cmd *cobra.Command, args []string) error {
	if rpcURL == "" && configFile == "" {
		return fmt.Errorf("specify --rpc-url or --config-file")
	}
	var results []checks.CheckResult
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if rpcURL != "" {
		client := scanner.NewClient(rpcURL)
		allChecks := checks.AllChecks()
		resultsChan := make(chan checks.CheckResult, len(allChecks))
		var wg sync.WaitGroup

		color.Cyan("🚀 Starting security audit against: %s", rpcURL)

		for _, check := range allChecks {
			wg.Add(1)
			go func(c checks.Check) {
				defer wg.Done()
				res, err := c.Run(ctx, client)
				if err != nil {
					resultsChan <- checks.CheckResult{
						Name:        c.Name(),
						Risk:        c.RiskLevel(),
						Description: c.Description(),
						Passed:      false,
						Details:     map[string]string{"error": err.Error()},
					}
					return
				}
				resultsChan <- res
			}(check)
		}

		wg.Wait()
		close(resultsChan)

		for res := range resultsChan {
			results = append(results, res)
			if res.Passed {
				color.Green("✅ [%s] %s", res.Risk, res.Name)
			} else {
				color.Red("❌ [%s] %s", res.Risk, res.Name)
			}
		}
	} else {
		check := &checks.ConfigFileCheck{}
		res, err := check.RunFile(ctx, configFile)
		if err != nil {
			return err
		}
		results = append(results, res)
	}

	switch outputFmt {
	case "json":
		rep := report.NewJSONReport(results)
		out, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		if outputFile != "" {
			return os.WriteFile(outputFile, out, 0644)
		}
		fmt.Println(string(out))
	case "html":
		rep := report.NewHTMLReport(results)
		if outputFile != "" {
			return os.WriteFile(outputFile, []byte(rep), 0644)
		}
		fmt.Println(rep)
	default:
		return fmt.Errorf("unsupported output format: %s", outputFmt)
	}
	return nil
}
