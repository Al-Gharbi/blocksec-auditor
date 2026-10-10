package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Al-Gharbi/blocksec-auditor/internal/checks"
	"github.com/Al-Gharbi/blocksec-auditor/internal/report"
	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
)

// version is overridden at build time: -ldflags "-X main.version=..."
var version = "0.2.0"

// Exit codes: 0 success / no finding at or above --fail-on, 1 findings at or
// above --fail-on, 2 usage error or the audit could not be performed.
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

const usageText = `Usage: blocksec-auditor <command> [options]

Commands:
  audit     Audit an EVM node over JSON-RPC and/or a node config file
  version   Print version

Run 'blocksec-auditor audit -h' for options.
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return exitError
	}
	switch args[0] {
	case "audit":
		return runAudit(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "blocksec-auditor %s\n", version)
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usageText)
		return exitOK
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usageText)
	return exitError
}

type auditOptions struct {
	rpcURL, configFile, output, outputFile, failOn string
	timeout                                        time.Duration
	minPeers                                       int
}

func runAudit(args []string, stdout, stderr io.Writer) int {
	var o auditOptions
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.rpcURL, "rpc-url", "", "JSON-RPC endpoint, e.g. http://localhost:8545")
	fs.StringVar(&o.configFile, "config-file", "", "path to a Geth (TOML) or Nethermind (JSON) config file")
	fs.StringVar(&o.output, "output", "text", "report format: text, json or html")
	fs.StringVar(&o.outputFile, "output-file", "", "write the report to this file instead of stdout")
	fs.StringVar(&o.failOn, "fail-on", "none", "exit 1 if a finding of at least this severity exists: none, low, medium, high, critical")
	fs.DurationVar(&o.timeout, "timeout", scanner.DefaultTimeout, "per-request timeout")
	fs.IntVar(&o.minPeers, "min-peers", checks.DefaultOptions().MinPeers, "peer count below which the peer check fails")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: blocksec-auditor audit [options]\n\nAt least one of --rpc-url or --config-file is required.\nAll RPC probes are read-only.\n\nOptions:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n", fs.Arg(0))
		return exitError
	}
	if o.rpcURL == "" && o.configFile == "" {
		fmt.Fprintln(stderr, "error: specify --rpc-url or --config-file")
		return exitError
	}
	switch o.output {
	case "text", "json", "html":
	default:
		fmt.Fprintf(stderr, "error: unsupported --output %q (use text, json or html)\n", o.output)
		return exitError
	}
	var failAt checks.RiskLevel
	if strings.ToLower(o.failOn) != "none" {
		r, ok := checks.ParseRisk(o.failOn)
		if !ok {
			fmt.Fprintf(stderr, "error: invalid --fail-on %q\n", o.failOn)
			return exitError
		}
		failAt = r
	}
	if o.minPeers < 0 || o.timeout <= 0 {
		fmt.Fprintln(stderr, "error: --min-peers must be >= 0 and --timeout > 0")
		return exitError
	}

	var results []checks.CheckResult
	var targets []string

	if o.rpcURL != "" {
		u, err := url.Parse(o.rpcURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			fmt.Fprintf(stderr, "error: --rpc-url must be an http(s) URL with a host, got %q\n", o.rpcURL)
			return exitError
		}
		targets = append(targets, o.rpcURL)
		cl := scanner.NewClientWithTimeout(o.rpcURL, o.timeout)
		if err := reachable(cl, o.timeout); err != nil {
			fmt.Fprintf(stderr, "error: %s is not a reachable JSON-RPC endpoint: %v\n", o.rpcURL, err)
			return exitError
		}
		results = append(results, runChecks(cl, checks.Options{MinPeers: o.minPeers}, o.timeout)...)
	}
	if o.configFile != "" {
		targets = append(targets, o.configFile)
		results = append(results, checks.AuditConfigFile(o.configFile))
	}

	rep := report.New(version, strings.Join(targets, ", "), time.Now(), results)
	if code := write(rep, o, stdout, stderr); code != exitOK {
		return code
	}
	if failAt != "" && checks.Worst(results).Rank() >= failAt.Rank() {
		return exitFindings
	}
	return exitOK
}

// reachable confirms the endpoint speaks JSON-RPC at all. A JSON-RPC error or
// an HTTP status counts as reachable (the checks will classify it); a
// transport failure or a non-JSON-RPC answer does not. Without this, every
// check on a dead endpoint used to be reported as passed.
func reachable(cl *scanner.Client, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err := cl.Call(ctx, "web3_clientVersion")
	var re *scanner.RPCError
	var he *scanner.HTTPError
	if err == nil || errors.As(err, &re) || errors.As(err, &he) {
		return nil
	}
	return err
}

// runChecks runs all checks concurrently and returns results in the stable
// order of checks.All().
func runChecks(cl *scanner.Client, o checks.Options, timeout time.Duration) []checks.CheckResult {
	list := checks.All()
	results := make([]checks.CheckResult, len(list))
	ctx, cancel := context.WithTimeout(context.Background(), 6*timeout)
	defer cancel()
	var wg sync.WaitGroup
	for i, c := range list {
		wg.Add(1)
		go func(i int, c checks.Check) {
			defer wg.Done()
			results[i] = c.Run(ctx, cl, o)
		}(i, c)
	}
	wg.Wait()
	return results
}

func write(rep report.Report, o auditOptions, stdout, stderr io.Writer) int {
	var w io.Writer = stdout
	var f *os.File
	if o.outputFile != "" {
		var err error
		// 0600: the report describes a node's weaknesses.
		f, err = os.OpenFile(o.outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitError
		}
		w = f
	}
	var err error
	switch o.output {
	case "json":
		err = rep.JSON(w)
	case "html":
		err = rep.HTML(w)
	default:
		rep.Text(w, f == nil && isTerminal(stdout) && os.Getenv("NO_COLOR") == "")
	}
	if f != nil {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			fmt.Fprintf(stderr, "report written to %s\n", o.outputFile)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: writing report: %v\n", err)
		return exitError
	}
	return exitOK
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
