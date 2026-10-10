package checks

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
)

// ---- RPC reachable without authentication --------------------------------

type rpcExposure struct{ base }

func NewRPCExposure() Check {
	return rpcExposure{base{
		id: "BSA-RPC-001", name: "RPC Reachable Without Authentication", risk: RiskHigh,
		desc:        "Checks whether the JSON-RPC endpoint answers requests without any authentication, as seen from where the scan runs",
		remediation: "Bind RPC to 127.0.0.1 or put it behind an authenticating reverse proxy / firewall allow-list; never expose it to the internet.",
	}}
}

func (c rpcExposure) Run(ctx context.Context, cl *scanner.Client, _ Options) CheckResult {
	if scanner.IsLoopbackHost(cl.Host()) {
		return c.skipped("target is a loopback address; run the scan from a different host to assess network exposure")
	}
	_, err := cl.Call(ctx, "net_version")
	var re *scanner.RPCError
	switch {
	case err == nil:
		return c.fail(RiskHigh, map[string]string{"method": "net_version", "result": "answered without credentials"})
	case scanner.IsAccessDenied(err):
		return c.pass(map[string]string{"result": err.Error() + " (access control in front of the node)"})
	case errors.As(err, &re):
		if looksLikeAuthError(re.Message) {
			return c.pass(map[string]string{"result": "JSON-RPC error indicates authentication: " + re.Message})
		}
		return c.fail(RiskHigh, map[string]string{"method": "net_version", "result": "JSON-RPC server responded without credentials: " + re.Message})
	default:
		return c.errored(err)
	}
}

func looksLikeAuthError(msg string) bool {
	m := strings.ToLower(msg)
	for _, k := range []string{"unauthor", "forbidden", "api key", "apikey", "authentication", "not allowed"} {
		if strings.Contains(m, k) {
			return true
		}
	}
	return false
}

// ---- TLS -------------------------------------------------------------------

type tlsCheck struct{ base }

func NewTLS() Check {
	return tlsCheck{base{
		id: "BSA-TLS-001", name: "RPC Transport Not Encrypted", risk: RiskHigh,
		desc:        "Verifies the RPC connection uses HTTPS (plain HTTP is accepted only for loopback targets)",
		remediation: "Terminate TLS in front of the node (nginx/Caddy with a valid certificate) and connect with https://.",
	}}
}

func (c tlsCheck) Run(_ context.Context, cl *scanner.Client, _ Options) CheckResult {
	u, err := url.Parse(cl.Endpoint)
	if err != nil {
		return c.errored(err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return c.pass(map[string]string{"scheme": "https"})
	case "http":
		if scanner.IsLoopbackHost(u.Hostname()) {
			return c.skipped("plain HTTP to a loopback address does not cross a network")
		}
		return c.fail(RiskHigh, map[string]string{"scheme": "http", "host": u.Hostname()})
	default:
		return c.errored(errors.New("unsupported scheme " + u.Scheme))
	}
}

// ---- CORS -------------------------------------------------------------------

type corsCheck struct{ base }

func NewCORS() Check {
	return corsCheck{base{
		id: "BSA-COR-001", name: "Permissive CORS Policy", risk: RiskMedium,
		desc:        "Checks whether the node allows arbitrary web origins (wildcard, reflected or null Origin) to call it from a browser",
		remediation: "Set the node's CORS allow-list to the exact origins that need it; do not use \"*\".",
	}}
}

// probeOrigin uses the reserved ".invalid" TLD (RFC 2606), so the probe can
// never name a real third-party site.
const probeOrigin = "https://blocksec-auditor-probe.invalid"

func (c corsCheck) Run(ctx context.Context, cl *scanner.Client, _ Options) CheckResult {
	h, err := cl.Preflight(ctx, probeOrigin)
	if err != nil {
		return c.errored(err)
	}
	acao := h.Get("Access-Control-Allow-Origin")
	creds := strings.EqualFold(h.Get("Access-Control-Allow-Credentials"), "true")
	d := map[string]interface{}{"allow_origin": acao, "allow_credentials": creds}
	switch acao {
	case "*":
		d["problem"] = "wildcard origin"
		return c.fail(RiskMedium, d)
	case probeOrigin:
		d["problem"] = "arbitrary Origin is reflected"
		return c.fail(RiskMedium, d)
	case "null":
		d["problem"] = "null origin allowed"
		return c.fail(RiskMedium, d)
	}
	return c.pass(d)
}
