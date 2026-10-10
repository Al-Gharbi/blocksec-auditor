package checks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
)

// ---- Administrative / wallet APIs -----------------------------------------

type adminAPI struct{ base }

func NewAdminAPI() Check {
	return adminAPI{base{
		id: "BSA-ADM-001", name: "Administrative or Wallet API Exposed", risk: RiskCritical,
		desc:        "Probes (read-only) whether admin_* / personal_* methods are reachable on the RPC endpoint",
		remediation: "Remove admin, personal and debug from the HTTP/WS module list; use IPC or an authenticated side channel for administration.",
	}}
}

// adminProbes are read-only methods. The original tool probed
// personal_newAccount, which CREATES an account on the node and writes a
// keystore file: a scanner must never change the state of its target.
var adminProbes = []string{"admin_nodeInfo", "admin_peers", "personal_listWallets", "personal_listAccounts"}

func (c adminAPI) Run(ctx context.Context, cl *scanner.Client, _ Options) CheckResult {
	outcome := map[string]string{}
	var exposed []string
	unknown := 0
	for _, m := range adminProbes {
		_, err := cl.Call(ctx, m)
		var re *scanner.RPCError
		switch {
		case err == nil:
			outcome[m] = "exposed"
			exposed = append(exposed, m)
		case scanner.IsMethodNotFound(err):
			outcome[m] = "absent"
		case scanner.IsAccessDenied(err):
			outcome[m] = "denied"
		case errors.As(err, &re) && re.Code == scanner.CodeInvalidParams:
			outcome[m] = "present (invalid params)"
			exposed = append(exposed, m)
		default:
			outcome[m] = "unknown: " + err.Error()
			unknown++
		}
	}
	d := map[string]interface{}{"methods": outcome, "exposed": exposed}
	if len(exposed) > 0 {
		return c.fail(exposureRisk(RiskCritical, scanner.IsLoopbackHost(cl.Host())), d)
	}
	if unknown == len(adminProbes) {
		return c.result(StatusError, c.risk, d)
	}
	return c.pass(d)
}

// ---- Accounts held by the node --------------------------------------------

type accounts struct{ base }

func NewAccounts() Check {
	return accounts{base{
		id: "BSA-ACC-001", name: "Node-Held Accounts Reachable Over RPC", risk: RiskHigh,
		desc:        "Checks whether eth_accounts lists accounts and, when the node reports wallet state, whether any is unlocked",
		remediation: "Do not keep funded keys in the node's keystore; sign with an external signer (e.g. Clef) and never leave accounts unlocked.",
	}}
}

type wallet struct {
	URL      string `json:"url"`
	Status   string `json:"status"`
	Accounts []struct {
		Address string `json:"address"`
	} `json:"accounts"`
}

func (c accounts) Run(ctx context.Context, cl *scanner.Client, _ Options) CheckResult {
	raw, err := cl.Call(ctx, "eth_accounts")
	if err != nil {
		if scanner.IsMethodNotFound(err) || scanner.IsAccessDenied(err) {
			return c.pass(map[string]string{"result": err.Error()})
		}
		return c.errored(err)
	}
	var addrs []string
	if err := json.Unmarshal(raw, &addrs); err != nil {
		return c.errored(err)
	}
	if len(addrs) == 0 {
		return c.pass(map[string]int{"accounts": 0})
	}
	loop := scanner.IsLoopbackHost(cl.Host())
	d := map[string]interface{}{"accounts": len(addrs)}

	// eth_accounts lists keystore accounts whether or not they are unlocked.
	// Geth's personal_listWallets reports a status per wallet, which is the
	// only read-only way to tell.
	if wr, werr := cl.Call(ctx, "personal_listWallets"); werr == nil {
		var ws []wallet
		if json.Unmarshal(wr, &ws) == nil {
			unlocked := 0
			for _, w := range ws {
				if strings.Contains(strings.ToLower(w.Status), "unlocked") {
					unlocked += max(len(w.Accounts), 1)
				}
			}
			d["unlocked_accounts"] = unlocked
			if unlocked > 0 {
				d["problem"] = "unlocked accounts can sign and send transactions via eth_sendTransaction"
				return c.fail(exposureRisk(RiskHigh, loop), d)
			}
			d["note"] = "accounts are present but all reported locked"
			return c.fail(RiskLow, d)
		}
	}
	d["note"] = "unlocked state could not be determined (node does not expose personal_listWallets)"
	return c.fail(exposureRisk(RiskMedium, loop), d)
}
